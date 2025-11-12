package plugins

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"

	"github.com/checkmarx/2ms/v4/engine/chunk"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	ErrHTTPSRequired = errors.New("must use https")
)

// CLI flags for Confluence.
const (
	flagSpaceIDs  = "space-ids"
	flagSpaceKeys = "space-keys"
	flagPageIDs   = "page-ids"
	flagUsername  = "username"
	flagToken     = "token"
	flagHistory   = "history"
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

	// Tracking (no extra HTTP requests):
	// queuedSpaceIDs: space IDs we are planning to query (dedup inputs before API calls).
	queuedSpaceIDs map[string]struct{}
	// returnedSpaceIDs: space IDs actually observed in returned pages (to detect space-ids that yielded no pages).
	returnedSpaceIDs map[string]struct{}
	// returnedPageIDs: page IDs actually emitted (prevents duplicates; also used to detect missing page-ids).
	returnedPageIDs map[string]struct{}
	// resolvedSpaceKeys: map of space-key -> space-id for keys that resolved (to detect keys that didn't resolve).
	resolvedSpaceKeys map[string]string
}

// NewConfluencePlugin constructs a new Confluence plugin with a default chunker.
func NewConfluencePlugin() IPlugin {
	return &ConfluencePlugin{
		chunker: chunk.New(),
	}
}

// GetName returns the CLI subcommand name for this plugin.
func (p *ConfluencePlugin) GetName() string { return "confluence" }

// DefineCommand wires the Cobra command, flags, and pre-run initialization.
func (p *ConfluencePlugin) DefineCommand(items chan ISourceItem, errs chan error) (*cobra.Command, error) {
	p.itemsChan = items
	p.errorsChan = errs

	var username string
	var token string

	cmd := &cobra.Command{
		Use:     fmt.Sprintf("%s <URL>", p.GetName()),
		Short:   "Scan Confluence Cloud",
		Long:    "Scan Confluence Cloud for sensitive information",
		Example: fmt.Sprintf("  2ms %s https://checkmarx.atlassian.net/wiki", p.GetName()),
		Args:    cobra.MatchAll(cobra.ExactArgs(1), isValidURL),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := p.initialize(args[0], username, token); err != nil {
				return err
			}
			if username == "" || token == "" {
				log.Warn().Msg("Confluence credentials not provided. The scan will run anonymously (public pages only).")
			}
			return nil
		},
		Run: func(cmd *cobra.Command, _ []string) {
			log.Info().Msg("Confluence plugin started")
			if err := p.walkAndEmitPages(context.Background()); err != nil {
				p.errorsChan <- err
				return
			}
			close(items)
		},
	}

	flags := cmd.Flags()
	flags.StringSliceVar(&p.SpaceIDs, flagSpaceIDs, []string{}, "Comma-separated list of Confluence space IDs to scan.")
	flags.StringSliceVar(&p.SpaceKeys, flagSpaceKeys, []string{}, "Comma-separated list of Confluence space keys to scan.")
	flags.StringSliceVar(&p.PageIDs, flagPageIDs, []string{}, "Comma-separated list of Confluence page IDs to scan.")
	flags.StringVar(&username, flagUsername, "", "Confluence user name or email for authentication.")
	flags.StringVar(&token, flagToken, "", "Confluence API/scoped token value.")
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
		return fmt.Errorf("invalid URL: %w", ErrHTTPSRequired)
	}
	if parsedURL.Host == "" {
		return fmt.Errorf("invalid URL: missing host")
	}
	return nil
}

// initialize stores the normalized base wiki URL and constructs the Confluence client.
// It validates the base by discovering the cloudId; if discovery fails, init fails.
func (p *ConfluencePlugin) initialize(base, username, token string) error {
	client, err := NewConfluenceClient(base, username, token)
	if err != nil {
		return err
	}
	p.client = client
	return nil
}

// walkAndEmitPages discovers pages by the provided selectors (space IDs, space keys, page IDs).
// If no selector is provided, it walks all accessible pages. Pages are de-duplicated by ID.
// Also tracks which selectors yielded results and logs warnings for invalid/inaccessible selectors,
// without issuing additional API requests.
func (p *ConfluencePlugin) walkAndEmitPages(ctx context.Context) error {
	// (Re)initialize tracking for this run.
	p.queuedSpaceIDs = make(map[string]struct{}, len(p.SpaceIDs))
	p.returnedSpaceIDs = make(map[string]struct{}, 256)
	p.returnedPageIDs = make(map[string]struct{}, len(p.PageIDs))
	p.resolvedSpaceKeys = make(map[string]string, 256)

	if len(p.SpaceIDs) > 0 {
		if err := p.scanBySpaceIDs(ctx); err != nil {
			return err
		}
	}

	if len(p.SpaceKeys) > 0 {
		if err := p.scanBySpaceKeys(ctx); err != nil {
			return err
		}
	}

	if len(p.PageIDs) > 0 {
		if err := p.scanByPageIDs(ctx); err != nil {
			return err
		}
	}

	if len(p.SpaceIDs) == 0 && len(p.SpaceKeys) == 0 && len(p.PageIDs) == 0 {
		if err := p.client.WalkAllPages(ctx, maxPageSize, func(page *Page) error {
			return p.emitUniquePage(ctx, page)
		}); err != nil {
			return err
		}
	}

	p.warnMissingSelectors()

	return nil
}

// scanBySpaceIDs walks pages in the explicitly provided space IDs (p.SpaceIDs).
// It deduplicates input space IDs with p.queuedSpaceIDs, batches requests (maxSpaceIDsPerRequest),
// and emits pages via emitUniquePage while tracking p.returnedPageIDs to avoid duplicates.
func (p *ConfluencePlugin) scanBySpaceIDs(ctx context.Context) error {
	var uniqueSpaceIDs []string
	for _, spaceID := range p.SpaceIDs {
		if _, alreadySeen := p.queuedSpaceIDs[spaceID]; alreadySeen {
			continue
		}
		p.queuedSpaceIDs[spaceID] = struct{}{}
		uniqueSpaceIDs = append(uniqueSpaceIDs, spaceID)
	}

	return p.walkPagesByIDBatches(
		ctx,
		uniqueSpaceIDs,
		maxSpaceIDsPerRequest,
		p.client.WalkPagesBySpaceIDs,
	)
}

// scanBySpaceKeys resolves space keys (p.SpaceKeys) to space IDs, deduplicates with
// p.queuedSpaceIDs, then walks pages by those IDs in batches. Each page is emitted via
// emitUniquePage, updating p.returnedPageIDs.
func (p *ConfluencePlugin) scanBySpaceKeys(ctx context.Context) error {
	for _, spaceKeyBatch := range chunkStrings(p.SpaceKeys, maxSpaceKeysPerRequest) {
		var newlyResolvedSpaceIDs []string
		if err := p.client.WalkSpacesByKeys(ctx, spaceKeyBatch, maxPageSize, func(space *Space) error {
			if space != nil && space.Key != "" && space.ID != "" {
				p.resolvedSpaceKeys[space.Key] = space.ID
			}
			if _, alreadySeen := p.queuedSpaceIDs[space.ID]; alreadySeen {
				return nil
			}
			p.queuedSpaceIDs[space.ID] = struct{}{}
			newlyResolvedSpaceIDs = append(newlyResolvedSpaceIDs, space.ID)
			return nil
		}); err != nil {
			return err
		}

		if err := p.walkPagesByIDBatches(
			ctx,
			newlyResolvedSpaceIDs,
			maxSpaceIDsPerRequest,
			p.client.WalkPagesBySpaceIDs,
		); err != nil {
			return err
		}
	}
	return nil
}

// scanByPageIDs walks the specific page IDs in p.PageIDs, batching requests (maxPageIDsPerRequest),
// and emits each page via emitUniquePage while tracking p.returnedPageIDs to avoid duplicates.
func (p *ConfluencePlugin) scanByPageIDs(ctx context.Context) error {
	return p.walkPagesByIDBatches(
		ctx,
		p.PageIDs,
		maxPageIDsPerRequest,
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
		tmp := *page
		tmp.Body.Storage = &struct {
			Value string `json:"value"`
		}{Value: chunkStr}

		p.itemsChan <- p.convertPageToItem(&tmp)
	}
}

// emitUniquePage emits the current version of a page (and, if enabled, its historical versions)
// ensuring each page ID is emitted only once. Also records the page SpaceID for selector warnings.
func (p *ConfluencePlugin) emitUniquePage(ctx context.Context, page *Page) error {
	if _, alreadySeen := p.returnedPageIDs[page.ID]; alreadySeen {
		return nil
	}
	p.returnedPageIDs[page.ID] = struct{}{}

	if page.SpaceID != "" {
		p.returnedSpaceIDs[page.SpaceID] = struct{}{}
	}

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

// convertPageToItem converts a Confluence Page into an ISourceItem.
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
	walker func(context.Context, []string, int, func(*Page) error) error,
) error {
	for _, idBatch := range chunkStrings(ids, perBatch) {
		if err := walker(ctx, idBatch, maxPageSize, func(page *Page) error {
			return p.emitUniquePage(ctx, page)
		}); err != nil {
			return err
		}
	}
	return nil
}

// differenceStrings returns the subset of wants not present in seen (map set).
func differenceStrings(wants []string, seen map[string]struct{}) []string {
	if len(wants) == 0 {
		return nil
	}
	var missing []string
	for _, w := range wants {
		if _, ok := seen[w]; !ok {
			missing = append(missing, w)
		}
	}
	return missing
}

// missingKeysFromResolved returns keys that did not resolve to any space (invisible or invalid).
func missingKeysFromResolved(requestedKeys []string, resolved map[string]string) []string {
	if len(requestedKeys) == 0 {
		return nil
	}
	var missing []string
	for _, k := range requestedKeys {
		if _, ok := resolved[k]; !ok {
			missing = append(missing, k)
		}
	}
	return missing
}

// dedupStringsStable returns a de-duplicated copy of input preserving order.
func dedupStringsStable(input []string) []string {
	if len(input) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(input))
	out := make([]string, 0, len(input))
	for _, v := range input {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// warnList logs a single warning with the sample values and, when applicable,
// appends "…and N more ..." to the same message.
func (p *ConfluencePlugin) warnList(label string, values []string) {
	const maxShow = 3
	if len(values) == 0 {
		return
	}

	// De-duplicate for cleaner logs.
	values = dedupStringsStable(values)

	show := values
	omitted := 0
	if len(values) > maxShow {
		show = values[:maxShow]
		omitted = len(values) - maxShow
	}
	msg := fmt.Sprintf("No results for some %s(s). They may be invalid, inaccessible, or empty.", label)

	ev := log.Warn().
		Str("selector", label).
		Strs("values", show)
	if omitted > 0 {
		ev = ev.Int("omitted", omitted)
	}
	ev.Msg(msg)
}

// warnMissingSelectors compares user-provided selectors with observed results and logs concise warnings.
func (p *ConfluencePlugin) warnMissingSelectors() {
	if len(p.PageIDs) > 0 {
		missingPages := differenceStrings(p.PageIDs, p.returnedPageIDs)
		p.warnList("page-id", missingPages)
	}
	if len(p.SpaceKeys) > 0 {
		missingKeys := missingKeysFromResolved(p.SpaceKeys, p.resolvedSpaceKeys)
		p.warnList("space-key", missingKeys)
	}
	if len(p.SpaceIDs) > 0 {
		missingSpaces := differenceStrings(p.SpaceIDs, p.returnedSpaceIDs)
		p.warnList("space-id", missingSpaces)
	}
}
