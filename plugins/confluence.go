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

	"github.com/checkmarx/2ms/v5/engine/chunk"
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

	flagMaxAPIResponseMB = "max-api-response-megabytes"
	flagMaxPageBodyMB    = "max-page-body-megabytes"
	flagMaxTotalScanMB   = "max-total-scan-megabytes"
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

	// bytesPerMegabyte is used to convert CLI megabyte values into bytes.
	bytesPerMegabyte = 1024 * 1024
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

	// returnedSpaceIDs records space IDs actually seen on pages we emitted.
	// Used after the run to warn about requested space-ids (or resolved keys)
	// that returned no pages (invalid, inaccessible, or empty).
	returnedSpaceIDs map[string]struct{}

	// returnedPageIDs records page IDs we have already emitted in this run.
	// Prevents duplicate emission and lets us warn about requested page-ids
	// that produced no results.
	returnedPageIDs map[string]struct{}

	// resolvedSpaceKeys records successful space-key to space-id resolutions from WalkSpacesByKeys.
	// Keys that do not appear here failed to resolve (invalid/inaccessible),
	// and will be included in the warning.
	resolvedSpaceKeys map[string]string

	// invalidSpaceIDs holds user-provided (or resolved) space-ids that failed numeric/length validation.
	invalidSpaceIDs map[string]struct{}

	// invalidPageIDs holds user-provided page-ids that failed numeric/length validation.
	invalidPageIDs map[string]struct{}

	// Optional limits (0 means "no limit").
	maxAPIResponseBytes int64
	maxTotalScanBytes   int64
	maxPageBodyBytes    int64
}

// NewConfluencePlugin constructs a new Confluence plugin with a default chunker.
func NewConfluencePlugin() IPlugin {
	return &ConfluencePlugin{
		chunker:           chunk.New(),
		returnedSpaceIDs:  map[string]struct{}{},
		returnedPageIDs:   map[string]struct{}{},
		resolvedSpaceKeys: map[string]string{},
		invalidSpaceIDs:   map[string]struct{}{},
		invalidPageIDs:    map[string]struct{}{},
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

	// CLI values in megabytes; converted to bytes in PreRunE.
	var maxAPIResponseMB int
	var maxPageBodyMB int
	var maxTotalScanMB int

	cmd := &cobra.Command{
		Use:     fmt.Sprintf("%s <URL>", p.GetName()),
		Short:   "Scan Confluence Cloud",
		Long:    "Scan Confluence Cloud for sensitive information",
		Example: fmt.Sprintf("  2ms %s https://checkmarx.atlassian.net/wiki", p.GetName()),
		Args:    cobra.MatchAll(cobra.ExactArgs(1), isValidURL),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			p.SpaceKeys = trimNonEmpty(p.SpaceKeys)
			p.SpaceIDs = trimNonEmpty(p.SpaceIDs)
			p.PageIDs = trimNonEmpty(p.PageIDs)

			// Convert per-run/response/page limits from megabytes to bytes.
			if maxAPIResponseMB > 0 {
				p.maxAPIResponseBytes = int64(maxAPIResponseMB) * bytesPerMegabyte
			}
			if maxTotalScanMB > 0 {
				p.maxTotalScanBytes = int64(maxTotalScanMB) * bytesPerMegabyte
			}
			if maxPageBodyMB > 0 {
				p.maxPageBodyBytes = int64(maxPageBodyMB) * bytesPerMegabyte
			}

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

	// Optional limits (0 disables each check).
	flags.IntVar(&maxAPIResponseMB, flagMaxAPIResponseMB, 0,
		"limit for per-request API response size in megabytes. When exceeded, the batch is skipped and a warning is logged.")
	flags.IntVar(&maxPageBodyMB, flagMaxPageBodyMB, 0,
		"limit for individual page body size in megabytes. Pages above this size are skipped and logged as warnings.")
	flags.IntVar(&maxTotalScanMB, flagMaxTotalScanMB, 0,
		"limit for total downloaded data in megabytes for this Confluence scan. When exceeded, scanning stops gracefully and logs a warning.")

	return cmd, nil
}

// trimNonEmpty trims whitespace from each element and returns only the non-empty results.
// It normalizes CLI inputs for space keys / space IDs / page IDs.
// Returns nil when the input is empty or when all elements are empty after trimming.
func trimNonEmpty(inputs []string) []string {
	if len(inputs) == 0 {
		return nil
	}
	trimmed := make([]string, 0, len(inputs))
	for _, raw := range inputs {
		if v := strings.TrimSpace(raw); v != "" {
			trimmed = append(trimmed, v)
		}
	}
	if len(trimmed) == 0 {
		return nil
	}
	return trimmed
}

// isValidURL validates the single CLI argument as an HTTPS URL.
func isValidURL(_ *cobra.Command, args []string) error {
	inputURL := strings.TrimSpace(args[0])
	parsedURL, err := url.Parse(inputURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if parsedURL.Scheme != schemeHTTPS {
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
	client, err := NewConfluenceClient(
		base,
		username,
		token,
		WithMaxAPIResponseBytes(p.maxAPIResponseBytes),
		WithMaxTotalScanBytes(p.maxTotalScanBytes),
		// Page-body size limit is enforced in the plugin layer so that
		// large-but-accessible pages still count as "seen".
	)
	if err != nil {
		return err
	}
	p.client = client
	return nil
}

// walkAndEmitPages discovers pages by the provided selectors (space IDs, space keys, page IDs).
// If no selector is provided, it walks all accessible pages. Pages are de-duplicated by ID.
// Also tracks which selectors yielded results and logs a single consolidated warning for
// invalid/unresolvable/inaccessible selectors, without issuing additional API requests.
func (p *ConfluencePlugin) walkAndEmitPages(ctx context.Context) error {
	handleTotalLimit := func(err error) error {
		if errors.Is(err, ErrTotalScanVolumeExceeded) {
			log.Warn().Msg("Some Confluence pages could not be processed because the scan reached the configured total-volume limit.")
			return nil
		}
		return err
	}

	if len(p.SpaceIDs) > 0 || len(p.SpaceKeys) > 0 {
		allSpaceIDs, err := p.resolveAndCollectSpaceIDs(ctx)
		if err != nil {
			return handleTotalLimit(err)
		}
		if err := p.scanBySpaceIDs(ctx, allSpaceIDs); err != nil {
			return handleTotalLimit(err)
		}
	}

	if len(p.PageIDs) > 0 {
		if err := p.scanByPageIDs(ctx); err != nil {
			return handleTotalLimit(err)
		}
	}

	if len(p.SpaceIDs) == 0 && len(p.SpaceKeys) == 0 && len(p.PageIDs) == 0 {
		if err := p.client.WalkAllPages(ctx, maxPageSize, func(page *Page) error {
			return p.emitUniquePage(ctx, page)
		}); err != nil {
			return handleTotalLimit(err)
		}
	}

	if msg := p.missingSelectorsWarningMessage(); msg != "" {
		log.Warn().Msg(msg)
	}

	if p.client.APIResponseLimitHit() {
		log.Warn().Msg("Some Confluence pages could not be processed because one or more API responses exceeded the configured size limit.")
	}

	return nil
}

// resolveAndCollectSpaceIDs resolves space keys into space IDs, merges them with the
// explicitly provided space IDs, validates user input, removes duplicates, and returns
// the unique set of space IDs to scan.
func (p *ConfluencePlugin) resolveAndCollectSpaceIDs(ctx context.Context) ([]string, error) {
	unique := make(map[string]struct{}, len(p.SpaceIDs)+len(p.SpaceKeys))

	for _, id := range p.SpaceIDs {
		if !isValidNumericID(id) {
			p.invalidSpaceIDs[id] = struct{}{}
			continue
		}
		unique[id] = struct{}{}
	}

	for _, batch := range chunkStrings(p.SpaceKeys, maxSpaceKeysPerRequest) {
		err := p.client.WalkSpacesByKeys(ctx, batch, maxPageSize, func(space *Space) error {
			p.resolvedSpaceKeys[space.Key] = space.ID

			unique[space.ID] = struct{}{}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	uniqueSpaceIDs := make([]string, 0, len(unique))
	for id := range unique {
		uniqueSpaceIDs = append(uniqueSpaceIDs, id)
	}
	return uniqueSpaceIDs, nil
}

// scanBySpaceIDs walks pages by the provided space IDs.
func (p *ConfluencePlugin) scanBySpaceIDs(ctx context.Context, ids []string) error {
	return p.walkPagesByIDBatches(
		ctx,
		ids,
		maxSpaceIDsPerRequest,
		p.client.WalkPagesBySpaceIDs,
	)
}

// scanByPageIDs walks the specific page IDs in p.PageIDs, batching requests (maxPageIDsPerRequest),
// and emits each page via emitUniquePage while tracking p.returnedPageIDs to avoid duplicates.
func (p *ConfluencePlugin) scanByPageIDs(ctx context.Context) error {
	valid := make([]string, 0, len(p.PageIDs))
	for _, id := range p.PageIDs {
		if !isValidNumericID(id) {
			p.invalidPageIDs[id] = struct{}{}
			continue
		}
		valid = append(valid, id)
	}

	return p.walkPagesByIDBatches(
		ctx,
		valid,
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

// shouldSkipPageBody applies the per-page body size limit (if configured).
// It logs a warning when the limit is exceeded and returns true to indicate
// that the page's content (and history) should be skipped.
func (p *ConfluencePlugin) shouldSkipPageBody(page *Page) bool {
	if p.maxPageBodyBytes == 0 || page == nil || page.Body.Storage == nil {
		return false
	}

	bodySize := int64(len(page.Body.Storage.Value))
	if bodySize <= p.maxPageBodyBytes {
		return false
	}

	log.Warn().
		Str("page_id", page.ID).
		Int64("body_bytes", bodySize).
		Msg("Skipping page content because the Confluence page body exceeded the configured size limit.")
	return true
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

	// Enforce page body size limit after marking the page as seen, so that
	// large-but-accessible pages are not misreported as missing or unauthorized.
	if p.shouldSkipPageBody(page) {
		return nil
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
		if p.shouldSkipPageBody(versionedPage) {
			return nil
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
	itemID := p.NewConfluenceItemID(page.ID, page.Version.Number)

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

	if baseLink, ok := page.Links["base"]; ok && baseLink != "" {
		return baseLink, true
	}

	return "", false
}

// walkPagesByIDBatches batches IDs and emits pages using the provided walker.
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

// differenceStrings returns the subset of wants not present in seen.
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

// missingKeysFromResolved returns the subset of requested space keys that did not
// resolve to any space (e.g., invalid or inaccessible).
func missingKeysFromResolved(requestedKeys []string, resolved map[string]string) []string {
	if len(requestedKeys) == 0 {
		return nil
	}
	var missing []string
	for _, k := range requestedKeys {
		if k == "" {
			continue
		}
		if _, ok := resolved[k]; !ok {
			missing = append(missing, k)
		}
	}
	return missing
}

// abbreviateMiddle shortens very long IDs/keys by keeping the first and last 10 runes.
// If the input is shorter than 30 runes, it is returned unchanged.
func abbreviateMiddle(s string) string {
	rs := []rune(s)
	if len(rs) < 30 {
		return s
	}
	return string(rs[:10]) + "..." + string(rs[len(rs)-10:])
}

// appendUniqueAbbreviated de-duplicates by the original value and appends
// display strings (abbreviated if long) into out.
func appendUniqueAbbreviated(values []string, seenOriginals map[string]struct{}, out *[]string) {
	for _, orig := range values {
		if orig == "" {
			continue
		}
		if _, dup := seenOriginals[orig]; dup {
			continue
		}
		seenOriginals[orig] = struct{}{}
		*out = append(*out, abbreviateMiddle(orig))
	}
}

// appendUniqueMapKeysAbbreviated collects keys from m and delegates to appendUniqueAbbreviated.
func appendUniqueMapKeysAbbreviated(m, seenOriginals map[string]struct{}, out *[]string) {
	if len(m) == 0 {
		return
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		if k == "" {
			continue
		}
		keys = append(keys, k)
	}
	appendUniqueAbbreviated(keys, seenOriginals, out)
}

// missingSelectorsWarningMessage builds one consolidated warning message showing up to maxShow examples across
// page IDs, space keys, and space IDs that could not be processed (invalid, non-existent,
// or no access). The rest are summarized as "+ N more".
// It returns an empty string when there's nothing to report.
func (p *ConfluencePlugin) missingSelectorsWarningMessage() string {
	seenOriginals := make(map[string]struct{})
	displaySamples := make([]string, 0, 16)

	if len(p.PageIDs) > 0 {
		appendUniqueAbbreviated(differenceStrings(p.PageIDs, p.returnedPageIDs), seenOriginals, &displaySamples)
	}
	if len(p.SpaceKeys) > 0 {
		appendUniqueAbbreviated(missingKeysFromResolved(p.SpaceKeys, p.resolvedSpaceKeys), seenOriginals, &displaySamples)
	}
	if len(p.SpaceIDs) > 0 {
		appendUniqueAbbreviated(differenceStrings(p.SpaceIDs, p.returnedSpaceIDs), seenOriginals, &displaySamples)
	}
	appendUniqueMapKeysAbbreviated(p.invalidPageIDs, seenOriginals, &displaySamples)
	appendUniqueMapKeysAbbreviated(p.invalidSpaceIDs, seenOriginals, &displaySamples)

	if len(displaySamples) == 0 {
		return ""
	}

	const maxShow = 4
	samplesToShow := displaySamples
	remainingCount := 0
	if len(displaySamples) > maxShow {
		samplesToShow = displaySamples[:maxShow]
		remainingCount = len(displaySamples) - maxShow
	}

	moreSuffix := ""
	if remainingCount > 0 {
		moreSuffix = fmt.Sprintf(" + %d more", remainingCount)
	}

	return fmt.Sprintf(
		"The following page IDs, space keys, or space IDs could not be processed because they either don’t exist or you don’t have access permissions: %s%s. These items were excluded from the scan.", //nolint:lll // long, user-facing message
		strings.Join(samplesToShow, ", "),
		moreSuffix,
	)
}

// isValidNumericID reports whether s consists only of ASCII digits ('0'–'9')
// and its byte length is in the range [1, 18]. Confluence typically returns
// HTTP 400 for IDs with length ≥ 19. Note that returning true here does not
// guarantee the ID actually exists or is accessible; it only means the value
// won’t be rejected due to format/length.
func isValidNumericID(s string) bool {
	if s == "" || len(s) >= 19 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// NewConfluenceItemID builds the item ID for a Confluence page.
func (p *ConfluencePlugin) NewConfluenceItemID(pageID string, version int) string {
	return fmt.Sprintf("%s-%s-%d", p.GetName(), pageID, version)
}

// ParseConfluenceItemID extracts the Confluence page ID from an item ID
// produced by NewConfluenceItemID. It returns ("", false) if the ID does not
// conform to the expected pattern.
func ParseConfluenceItemID(id string) (string, bool) {
	parts := strings.Split(id, "-")
	if len(parts) != 3 {
		return "", false
	}

	// Last segment must be an integer version.
	if _, err := strconv.Atoi(parts[len(parts)-1]); err != nil {
		return "", false
	}

	// Second-to-last segment must be a valid numeric pageId.
	pageID := parts[len(parts)-2]
	if !isValidNumericID(pageID) {
		return "", false
	}

	return pageID, true
}
