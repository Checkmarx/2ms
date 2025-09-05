package plugins

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

const (
	flagSpaceIDs  = "space-ids"
	flagSpaceKeys = "space-keys"
	flagPageIDs   = "page-ids"
	flagUsername  = "username"
	flagToken     = "token"
	flagHistory   = "history"

	// Confluence Cloud REST API v2 constraints
	maxPageIDsPerRequest   = 250
	maxSpaceIDsPerRequest  = 100
	maxSpaceKeysPerRequest = 250
	maxPageSize            = 250

	httpTimeout = 60 * time.Second
)

type ConfluencePlugin struct {
	Plugin

	SpaceIDs  []string
	SpaceKeys []string
	PageIDs   []string
	History   bool

	baseWikiURL string
	httpClient  *http.Client
	username    string
	token       string

	itemsChan  chan ISourceItem
	errorsChan chan error

	client ConfluenceClient
}

func (p *ConfluencePlugin) GetName() string { return "confluence" }

func (p *ConfluencePlugin) DefineCommand(items chan ISourceItem, errs chan error) (*cobra.Command, error) {
	p.itemsChan = items
	p.errorsChan = errs

	cmd := &cobra.Command{
		Use:     fmt.Sprintf("%s <URL>", p.GetName()),
		Short:   "Scan Confluence Cloud",
		Long:    "Scan Confluence Cloud pages for sensitive information",
		Example: fmt.Sprintf("  2ms %s https://checkmarx.atlassian.net/wiki", p.GetName()),
		Args:    cobra.MatchAll(cobra.ExactArgs(1), validateConfluenceURLArg),
		Run: func(cmd *cobra.Command, args []string) {
			log.Info().Msg("Confluence plugin started")
			p.initialize(args[0])
			if p.username == "" || p.token == "" {
				log.Warn().Msg("Confluence credentials not provided. The scan will run anonymously (public pages only).")
			}
			if err := p.runScan(context.Background()); err != nil {
				p.errorsChan <- err
			}
			close(items)
		},
	}

	flags := cmd.Flags()
	flags.StringSliceVar(&p.SpaceIDs, flagSpaceIDs, []string{}, "Comma-separated list of Confluence space IDs to scan.")
	flags.StringSliceVar(&p.SpaceKeys, flagSpaceKeys, []string{}, "Comma-separated list of Confluence space keys to scan.")
	flags.StringSliceVar(&p.PageIDs, flagPageIDs, []string{}, "Comma-separated list of Confluence page IDs to scan.")
	flags.StringVar(&p.username, flagUsername, "", "Confluence user name or email for authentication.")
	flags.StringVar(&p.token, flagToken, "", "Confluence API token for authentication.")
	flags.BoolVar(&p.History, flagHistory, false, "Also scan all page revisions (all versions).")

	return cmd, nil
}

func validateConfluenceURLArg(_ *cobra.Command, args []string) error {
	inputURL := strings.TrimSpace(args[0])

	parsedURL, err := url.Parse(inputURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if parsedURL.Scheme != "https" {
		return fmt.Errorf("invalid URL: must use https")
	}

	// Accept "/wiki" or "/wiki/"
	normalizedPath := strings.TrimRight(parsedURL.Path, "/")
	if normalizedPath != "/wiki" {
		return fmt.Errorf("invalid URL path: expected https://<company>.atlassian.net/wiki")
	}
	return nil
}

func (p *ConfluencePlugin) initialize(base string) {
	p.baseWikiURL = strings.TrimRight(base, "/")
	p.httpClient = &http.Client{Timeout: httpTimeout}
	p.client = &httpConfluenceClient{
		baseWikiURL: p.baseWikiURL,
		httpClient:  p.httpClient,
		username:    p.username,
		token:       p.token,
	}
}

func (p *ConfluencePlugin) runScan(ctx context.Context) error {
	pages, err := p.resolvePagesToScan(ctx)
	if err != nil {
		return err
	}

	siteBase := p.baseWikiURL

	for _, page := range pages {
		itemID := fmt.Sprintf("%s-%s", p.GetName(), page.ID)
		p.itemsChan <- convertPageToItem(page, itemID, siteBase, 0)

		if p.History {
			versionNumbers, err := p.client.ListPageVersionNumbers(ctx, page.ID, maxPageSize)
			if err != nil {
				return err
			}
			current := page.Version.Number
			for _, v := range versionNumbers {
				if v == current {
					continue // already emitted current version
				}
				versioned, err := p.client.FetchPageVersion(ctx, page.ID, v)
				if err != nil {
					return err
				}
				versionItemID := fmt.Sprintf("%s-%s-v%d", p.GetName(), versioned.ID, v)
				p.itemsChan <- convertPageToItem(versioned, versionItemID, siteBase, v)
			}
		}
	}
	return nil
}

func (p *ConfluencePlugin) resolvePagesToScan(ctx context.Context) ([]Page, error) {
	pagesByID := make(map[string]Page)
	spacesSeen := make(map[string]struct{})

	if len(p.SpaceIDs) > 0 {
		if err := p.collectPagesBySpaceIDs(ctx, spacesSeen, pagesByID); err != nil {
			return nil, err
		}
	}
	if len(p.SpaceKeys) > 0 {
		if err := p.collectPagesBySpaceKeys(ctx, spacesSeen, pagesByID); err != nil {
			return nil, err
		}
	}
	if len(p.PageIDs) > 0 {
		if err := p.collectPagesByPageIDs(ctx, pagesByID); err != nil {
			return nil, err
		}
	}

	// when no filters are provided
	if len(p.SpaceIDs) == 0 && len(p.SpaceKeys) == 0 && len(p.PageIDs) == 0 {
		if err := p.collectAllPages(ctx, pagesByID); err != nil {
			return nil, err
		}
	}

	collected := make([]Page, 0, len(pagesByID))
	for _, page := range pagesByID {
		collected = append(collected, page)
	}
	return collected, nil
}

// collectPagesBySpaceIDs fetches pages for --space-ids, deduping via spacesSeen.
func (p *ConfluencePlugin) collectPagesBySpaceIDs(
	ctx context.Context,
	spacesSeen map[string]struct{},
	pagesByID map[string]Page,
) error {
	if len(p.SpaceIDs) == 0 {
		return nil
	}
	var uniqueSpaceIDs []string
	for _, spaceID := range p.SpaceIDs {
		if _, dup := spacesSeen[spaceID]; dup {
			continue
		}
		spacesSeen[spaceID] = struct{}{}
		uniqueSpaceIDs = append(uniqueSpaceIDs, spaceID)
	}
	for _, spaceIDBatch := range chunkStrings(uniqueSpaceIDs, maxSpaceIDsPerRequest) {
		pages, err := p.client.ListPagesBySpaceIDs(ctx, spaceIDBatch, maxPageSize)
		if err != nil {
			return err
		}
		for _, page := range pages {
			pagesByID[page.ID] = page
		}
	}
	return nil
}

// collectPagesBySpaceKeys resolves --space-keys to IDs, skips already-seen IDs,
// and fetches pages for the remaining space IDs.
func (p *ConfluencePlugin) collectPagesBySpaceKeys(
	ctx context.Context,
	spacesSeen map[string]struct{},
	pagesByID map[string]Page,
) error {
	if len(p.SpaceKeys) == 0 {
		return nil
	}
	for _, keyBatch := range chunkStrings(p.SpaceKeys, maxSpaceKeysPerRequest) {
		spaces, err := p.client.ListSpacesByKeys(ctx, keyBatch, maxPageSize)
		if err != nil {
			return err
		}
		var newSpaceIDs []string
		for _, space := range spaces {
			if space.ID == "" {
				continue
			}
			if _, seen := spacesSeen[space.ID]; seen {
				continue
			}
			spacesSeen[space.ID] = struct{}{}
			newSpaceIDs = append(newSpaceIDs, space.ID)
		}
		for _, spaceIDBatch := range chunkStrings(newSpaceIDs, maxSpaceIDsPerRequest) {
			pages, err := p.client.ListPagesBySpaceIDs(ctx, spaceIDBatch, maxPageSize)
			if err != nil {
				return err
			}
			for _, page := range pages {
				pagesByID[page.ID] = page
			}
		}
	}
	return nil
}

// collectPagesByPageIDs fetches pages for --page-ids.
func (p *ConfluencePlugin) collectPagesByPageIDs(ctx context.Context, pagesByID map[string]Page) error {
	if len(p.PageIDs) == 0 {
		return nil
	}
	for _, pageIDBatch := range chunkStrings(p.PageIDs, maxPageIDsPerRequest) {
		pages, err := p.client.ListPagesByIDs(ctx, pageIDBatch, maxPageSize)
		if err != nil {
			return err
		}
		for _, page := range pages {
			pagesByID[page.ID] = page
		}
	}
	return nil
}

// collectAllPages lists all visible pages (paginated via Link) and merges into pagesByID.
func (p *ConfluencePlugin) collectAllPages(ctx context.Context, pagesByID map[string]Page) error {
	pages, err := p.client.ListAllPages(ctx, maxPageSize)
	if err != nil {
		return err
	}
	for _, page := range pages {
		pagesByID[page.ID] = page
	}
	return nil
}

func chunkStrings(input []string, chunkSize int) [][]string {
	var chunks [][]string
	for start := 0; start < len(input); start += chunkSize {
		end := start + chunkSize
		if end > len(input) {
			end = len(input)
		}
		chunks = append(chunks, input[start:end])
	}
	return chunks
}

func convertPageToItem(page Page, itemID string, wikiBaseURL string, versionNumber int) ISourceItem {
	var sourceURL string

	if page.Links != nil {
		if webUIPath, ok := page.Links["webui"]; ok && webUIPath != "" {
			// Ensure base ends with "/wiki/" and make webUIPath relative before resolving.
			baseURL, _ := url.Parse(strings.TrimRight(wikiBaseURL, "/") + "/") // e.g., https://tenant.atlassian.net/wiki/
			relativeURL, err := url.Parse(strings.TrimPrefix(webUIPath, "/"))  // "pages/viewpage.action?..."
			if err == nil {
				resolvedURL := baseURL.ResolveReference(relativeURL) // preserves /wiki
				if versionNumber > 0 {
					queryValues := resolvedURL.Query()
					queryValues.Set("pageVersion", strconv.Itoa(versionNumber))
					resolvedURL.RawQuery = queryValues.Encode()
				}
				sourceURL = resolvedURL.String()
			}
		} else if baseLink, ok := page.Links["base"]; ok && baseLink != "" {
			sourceURL = baseLink
		}
	}

	content := ""
	if page.Body.Storage != nil {
		content = page.Body.Storage.Value
	}

	return &item{
		ID:      itemID,
		Source:  sourceURL,
		Content: &content,
	}
}
