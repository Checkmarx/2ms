package plugins

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"

	"github.com/checkmarx/2ms/v4/engine/chunk"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

// CLI flags for Confluence.
const (
	flagSpaceIDs   = "space-ids"
	flagSpaceKeys  = "space-keys"
	flagPageIDs    = "page-ids"
	flagUsername   = "username"
	flagTokenType  = "token-type"  // "classic" or "scoped"
	flagTokenValue = "token-value" // required when token-type is set
	flagHistory    = "history"
)

// Confluence Cloud REST API v2 per-request limits (server caps by endpoint/param).
const (
	// maxPageIDsPerRequest is the per-request server cap for the number of page IDs
	// accepted by GET /pages via the ids= query parameter.
	maxPageIDsPerRequest = 250

	// maxSpaceIDsPerRequest is the per-request server cap for the number of space IDs
	// accepted by GET /pages via the space-id= query parameter.
	maxSpaceIDsPerRequest = 100

	// maxSpaceKeysPerRequest is the per-request server cap for the number of space keys
	// accepted by GET /spaces via the keys= query parameter.
	maxSpaceKeysPerRequest = 250

	// maxPageSize is the requested number of items per page in paginated responses.
	// Confluence v2 accepts 1–250; we use 250 to minimize requests so we're less likely to hit rate limits.
	maxPageSize = 250
)

type TokenType string

const (
	TokenClassic TokenType = "classic"
	TokenScoped  TokenType = "scoped"
)

type ConfluencePlugin struct {
	Plugin

	SpaceIDs  []string
	SpaceKeys []string
	PageIDs   []string
	History   bool

	itemsChan  chan ISourceItem
	errorsChan chan error

	client  ConfluenceClient
	chunker chunk.IChunk
}

func NewConfluencePlugin() IPlugin {
	return &ConfluencePlugin{
		chunker: chunk.New(),
	}
}

func (p *ConfluencePlugin) GetName() string { return "confluence" }

func (p *ConfluencePlugin) DefineCommand(items chan ISourceItem, errs chan error) (*cobra.Command, error) {
	p.itemsChan = items
	p.errorsChan = errs

	var username string
	var tokenType TokenType
	var tokenValue string

	cmd := &cobra.Command{
		Use:     fmt.Sprintf("%s <URL>", p.GetName()),
		Short:   "Scan Confluence Cloud",
		Long:    "Scan Confluence Cloud for sensitive information",
		Example: fmt.Sprintf("  2ms %s https://checkmarx.atlassian.net/wiki", p.GetName()),
		Args:    cobra.MatchAll(cobra.ExactArgs(1), isValidURL),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			tokenType = TokenType(strings.ToLower(string(tokenType)))
			if tokenValue != "" && tokenType == "" {
				return fmt.Errorf("--%s must be set when --%s is provided", flagTokenType, flagTokenValue)
			}
			if !isValidTokenType(tokenType) {
				return fmt.Errorf("invalid --%s %q; valid values are %q or %q",
					flagTokenType, tokenType, TokenClassic, TokenScoped)
			}
			if tokenType != "" && tokenValue == "" {
				return fmt.Errorf("--%s requires --%s", flagTokenType, flagTokenValue)
			}
			if err := p.initialize(args[0], username, tokenType, tokenValue); err != nil {
				return err
			}
			if username == "" || tokenValue == "" {
				log.Warn().Msg("Confluence credentials not provided. The scan will run anonymously (public pages only).")
			}
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			defer close(items)
			log.Info().Msg("Confluence plugin started")
			if err := p.walkAndEmitPages(context.Background()); err != nil {
				p.errorsChan <- err
				return
			}
		},
	}

	flags := cmd.Flags()
	flags.StringSliceVar(&p.SpaceIDs, flagSpaceIDs, []string{}, "Comma-separated list of Confluence space IDs to scan.")
	flags.StringSliceVar(&p.SpaceKeys, flagSpaceKeys, []string{}, "Comma-separated list of Confluence space keys to scan.")
	flags.StringSliceVar(&p.PageIDs, flagPageIDs, []string{}, "Comma-separated list of Confluence page IDs to scan.")
	flags.StringVar(&username, flagUsername, "", "Confluence user name or email for authentication.")
	flags.StringVar((*string)(&tokenType), flagTokenType, "", `Token type: "classic" or "scoped".`)
	flags.StringVar(&tokenValue, flagTokenValue, "", "Token value.")
	flags.BoolVar(&p.History, flagHistory, false, "Also scan all page revisions (all versions).")

	return cmd, nil
}

// isValidURL validates the single CLI argument as an HTTPS URL.
func isValidURL(_ *cobra.Command, args []string) error {
	inputURL := strings.TrimSpace(args[0])
	parsedURL, err := url.Parse(inputURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if parsedURL.Scheme != "https" {
		return fmt.Errorf("invalid URL: must use https")
	}
	return nil
}

// isValidTokenType reports whether the provided tokenType is supported.
// Valid values are the empty string (no auth), "classic", and "scoped".
func isValidTokenType(tokenType TokenType) bool {
	switch tokenType {
	case "", TokenClassic, TokenScoped:
		return true
	default:
		return false
	}
}

// initialize stores the base wiki URL and constructs the Confluence client.
func (p *ConfluencePlugin) initialize(base string, username string, tokenType TokenType, tokenValue string) error {
	baseWikiURL := strings.TrimRight(base, "/")

	client, err := NewConfluenceClient(baseWikiURL, username, tokenType, tokenValue)
	if err != nil {
		return err
	}
	p.client = client

	return nil
}

// walkAndEmitPages discovers pages by the provided selectors (space IDs, space keys, page IDs).
// If no selector is provided, it walks all accessible pages. Pages are de-duplicated by ID.
func (p *ConfluencePlugin) walkAndEmitPages(ctx context.Context) error {
	seenPageIDs := make(map[string]struct{}, len(p.PageIDs))
	seenSpaceIDs := make(map[string]struct{}, len(p.SpaceIDs))

	if len(p.SpaceIDs) > 0 {
		if err := p.scanBySpaceIDs(ctx, seenPageIDs, seenSpaceIDs); err != nil {
			return err
		}
	}

	if len(p.SpaceKeys) > 0 {
		if err := p.scanBySpaceKeys(ctx, seenPageIDs, seenSpaceIDs); err != nil {
			return err
		}
	}

	if len(p.PageIDs) > 0 {
		if err := p.scanByPageIDs(ctx, seenPageIDs); err != nil {
			return err
		}
	}

	if len(p.SpaceIDs) == 0 && len(p.SpaceKeys) == 0 && len(p.PageIDs) == 0 {
		if err := p.client.WalkAllPages(ctx, maxPageSize, func(page *Page) error {
			return p.emitUniquePage(ctx, page, seenPageIDs)
		}); err != nil {
			return err
		}
	}

	return nil
}

// scanBySpaceIDs walks pages in the explicitly provided space IDs (p.SpaceIDs).
// It deduplicates space IDs with seenSpaceIDs, batches requests (maxSpaceIDsPerRequest),
// and emits pages via emitUniquePage while tracking seenPageIDs.
func (p *ConfluencePlugin) scanBySpaceIDs(ctx context.Context, seenPageIDs, seenSpaceIDs map[string]struct{}) error {
	var uniqueSpaceIDs []string
	for _, spaceID := range p.SpaceIDs {
		if _, alreadySeen := seenSpaceIDs[spaceID]; alreadySeen {
			continue
		}
		seenSpaceIDs[spaceID] = struct{}{}
		uniqueSpaceIDs = append(uniqueSpaceIDs, spaceID)
	}

	return p.walkPagesByIDBatches(
		ctx,
		uniqueSpaceIDs,
		maxSpaceIDsPerRequest,
		seenPageIDs,
		p.client.WalkPagesBySpaceIDs,
	)
}

// scanBySpaceKeys resolves space keys (p.SpaceKeys) to space IDs, deduplicates with
// seenSpaceIDs, then walks pages by those IDs in batches. Each page is emitted via
// emitUniquePage, updating seenPageIDs.
func (p *ConfluencePlugin) scanBySpaceKeys(ctx context.Context, seenPageIDs, seenSpaceIDs map[string]struct{}) error {
	for _, spaceKeyBatch := range chunkStrings(p.SpaceKeys, maxSpaceKeysPerRequest) {
		var newlyResolvedSpaceIDs []string
		if err := p.client.WalkSpacesByKeys(ctx, spaceKeyBatch, maxPageSize, func(space *Space) error {
			if _, alreadySeen := seenSpaceIDs[space.ID]; alreadySeen {
				return nil
			}
			seenSpaceIDs[space.ID] = struct{}{}
			newlyResolvedSpaceIDs = append(newlyResolvedSpaceIDs, space.ID)
			return nil
		}); err != nil {
			return err
		}

		if err := p.walkPagesByIDBatches(
			ctx,
			newlyResolvedSpaceIDs,
			maxSpaceIDsPerRequest,
			seenPageIDs,
			p.client.WalkPagesBySpaceIDs,
		); err != nil {
			return err
		}
	}
	return nil
}

// scanByPageIDs walks the specific page IDs in p.PageIDs, batching requests (maxPageIDsPerRequest),
// and emits each page via emitUniquePage while tracking seenPageIDs to avoid duplicates.
func (p *ConfluencePlugin) scanByPageIDs(ctx context.Context, seenPageIDs map[string]struct{}) error {
	return p.walkPagesByIDBatches(
		ctx,
		p.PageIDs,
		maxPageIDsPerRequest,
		seenPageIDs,
		p.client.WalkPagesByIDs,
	)
}

// emitInChunks emits page content as one or many items.
func (p *ConfluencePlugin) emitInChunks(page *Page) error {
	if page.Body.Storage == nil {
		return nil
	}

	if len(page.Body.Storage.Value) < int(p.chunker.GetFileThreshold()) {
		p.itemsChan <- p.convertPageToItem(page)
		return nil
	}

	reader := bufio.NewReaderSize(
		strings.NewReader(page.Body.Storage.Value), p.chunker.GetSize()+p.chunker.GetMaxPeekSize(),
	)

	// We don't care about line-count logic here
	totalLines := -1

	for {
		chunkStr, err := p.chunker.ReadChunk(reader, totalLines)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("failed to read chunk for page %s: %w", page.ID, err)
		}
		if chunkStr == "" {
			// nothing more to emit
			return nil
		}

		tmp := *page
		tmp.Body.Storage = &struct {
			Value string `json:"value"`
		}{Value: chunkStr}

		p.itemsChan <- p.convertPageToItem(&tmp)
	}
}

// emitUniquePage emits the current version of a page (and, if enabled, its historical versions)
// ensuring each page ID is emitted only once.
func (p *ConfluencePlugin) emitUniquePage(ctx context.Context, page *Page, seenPageIDs map[string]struct{}) error {
	if _, alreadySeen := seenPageIDs[page.ID]; alreadySeen {
		return nil
	}
	seenPageIDs[page.ID] = struct{}{}

	// current version
	if err := p.emitInChunks(page); err != nil {
		return err
	}

	if p.History {
		if err := p.emitHistory(ctx, page); err != nil {
			return err
		}
	}
	return nil
}

// emitHistory enumerates all versions of a page and emits each version
// except the current one (which is already emitted by emitUniquePage).
func (p *ConfluencePlugin) emitHistory(ctx context.Context, page *Page) error {
	current := page.Version.Number
	return p.client.WalkPageVersions(ctx, page.ID, maxPageSize, func(versionNumber int) error {
		if versionNumber == current {
			return nil // already emitted current version
		}
		versionedPage, err := p.client.FetchPageAtVersion(ctx, page.ID, versionNumber)
		if err != nil {
			return err
		}
		return p.emitInChunks(versionedPage)
	})
}

// chunkStrings splits a slice into chunks of at most chunkSize elements.
func chunkStrings(input []string, chunkSize int) [][]string {
	if chunkSize <= 0 || len(input) == 0 {
		return nil
	}
	var chunks [][]string
	for startIndex := 0; startIndex < len(input); startIndex += chunkSize {
		endIndex := min(startIndex+chunkSize, len(input))
		chunks = append(chunks, input[startIndex:endIndex])
	}
	return chunks
}

// convertPageToItem converts a Confluence Page into an ISourceItem
func (p *ConfluencePlugin) convertPageToItem(page *Page) ISourceItem {
	itemID := fmt.Sprintf("%s-%s-%s", p.GetName(), page.ID, strconv.Itoa(page.Version.Number))

	sourceURL := ""
	if resolvedURL, ok := p.resolveConfluenceSourceURL(page, page.Version.Number); ok {
		sourceURL = resolvedURL
	}

	var content *string
	if page.Body.Storage != nil {
		content = &page.Body.Storage.Value
	}

	return &item{
		ID:      itemID,
		Source:  sourceURL,
		Content: content,
	}
}

// resolveConfluenceSourceURL resolves a URL for a page.
// It prefers the "_links.webui" path and appends pageVersion.
// Falls back to "_links.base" when webui is unavailable.
func (p *ConfluencePlugin) resolveConfluenceSourceURL(page *Page, versionNumber int) (string, bool) {
	if page.Links == nil {
		return "", false
	}

	// Prefer "webui"
	if webUIPath, ok := page.Links["webui"]; ok && webUIPath != "" {
		baseURL, err := url.Parse(strings.TrimRight(p.client.WikiBaseURL(), "/") + "/") // e.g., https://tenant.atlassian.net/wiki/
		if err != nil {
			return "", false
		}
		relativeURL, err := url.Parse(strings.TrimPrefix(webUIPath, "/")) // "pages/viewpage.action?..."
		if err != nil {
			return "", false
		}
		resolvedURL := baseURL.ResolveReference(relativeURL) // preserves /wiki
		queryValues := resolvedURL.Query()
		queryValues.Set("pageVersion", strconv.Itoa(versionNumber))
		resolvedURL.RawQuery = queryValues.Encode()
		return resolvedURL.String(), true
	}

	// Fallback: "_links.base"
	if baseLink, ok := page.Links["base"]; ok && baseLink != "" {
		return baseLink, true
	}

	return "", false
}

// walkPagesByIDBatches batch IDs and emit pages using the provided walker.
func (p *ConfluencePlugin) walkPagesByIDBatches(
	ctx context.Context,
	ids []string,
	perBatch int,
	seenPageIDs map[string]struct{},
	walker func(context.Context, []string, int, func(*Page) error) error,
) error {
	for _, idBatch := range chunkStrings(ids, perBatch) {
		if err := walker(ctx, idBatch, maxPageSize, func(page *Page) error {
			return p.emitUniquePage(ctx, page, seenPageIDs)
		}); err != nil {
			return err
		}
	}
	return nil
}
