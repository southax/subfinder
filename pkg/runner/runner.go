package runner

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	contextutil "github.com/projectdiscovery/utils/context"
	fileutil "github.com/projectdiscovery/utils/file"
	mapsutil "github.com/projectdiscovery/utils/maps"

	"github.com/southax/subfinder/v2/pkg/passive"
	"github.com/southax/subfinder/v2/pkg/resolve"
	"github.com/southax/subfinder/v2/pkg/subscraping"
)

// Runner is an instance of the subdomain enumeration
// client used to orchestrate the whole process.
type Runner struct {
	options           *Options
	passiveAgent      *passive.Agent
	resolverClient    *resolve.Resolver
	rateLimit         *subscraping.CustomRateLimit
	newPassiveAgent   func() *passive.Agent
	sharedRateLimiter subscraping.RequestLimiter
	outputMu          *sync.Mutex
	domainOutput      bool
	matchRegexes      []*regexp.Regexp
	filterRegexes     []*regexp.Regexp
	ndxerKeys         []string
	related           *relatedSettings
	relatedTag        *relatedTag
}

// NewRunner creates a new runner struct instance by parsing
// the configuration options, configuring sources, reading lists
// and setting up loggers, etc.
func NewRunner(options *Options) (*Runner, error) {
	options.ConfigureOutput()
	runner := &Runner{options: options}
	if err := runner.compileFilters(); err != nil {
		return nil, err
	}

	var providerKeys map[string][]string

	// Check if the application loading with any provider configuration, then take it
	// Otherwise load the default provider config
	if fileutil.FileExists(options.ProviderConfig) {
		gologger.Info().Msgf("Loading provider config from %s", options.ProviderConfig)
		providerKeys = options.loadProvidersFrom(options.ProviderConfig)
	} else {
		gologger.Info().Msgf("Loading provider config from the default location: %s", defaultProviderConfigLocation)
		providerKeys = options.loadProvidersFrom(defaultProviderConfigLocation)
	}

	// Initialize the passive subdomain enumeration engine
	runner.initializePassiveEngine(providerKeys)

	// Related-scope expansion is on whenever an ndxer key is configured.
	if err := runner.initializeRelated(); err != nil {
		return nil, err
	}

	// Initialize the subdomain resolver
	err := runner.initializeResolver()
	if err != nil {
		return nil, err
	}

	// Initialize the custom rate limit
	runner.rateLimit = &subscraping.CustomRateLimit{
		Custom: mapsutil.SyncLockMap[string, uint]{
			Map: make(map[string]uint),
		},
		CustomDuration: mapsutil.SyncLockMap[string, time.Duration]{
			Map: make(map[string]time.Duration),
		},
	}

	for source, sourceRateLimit := range options.RateLimits.AsMap() {
		if sourceRateLimit.MaxCount > 0 && sourceRateLimit.MaxCount <= math.MaxUint {
			_ = runner.rateLimit.Custom.Set(source, sourceRateLimit.MaxCount)
			if sourceRateLimit.Duration > 0 {
				_ = runner.rateLimit.CustomDuration.Set(source, sourceRateLimit.Duration)
			}
		}
	}

	return runner, nil
}

// RunEnumeration wraps RunEnumerationWithCtx with an empty context
func (r *Runner) RunEnumeration() error {
	ctx, _ := contextutil.WithValues(context.Background(), contextutil.ContextArg("All"), contextutil.ContextArg(strconv.FormatBool(r.options.All)))
	return r.RunEnumerationWithCtx(ctx)
}

// RunEnumerationWithCtx runs the subdomain enumeration flow on the targets specified
func (r *Runner) RunEnumerationWithCtx(ctx context.Context) error {
	outputs := []io.Writer{r.options.Output}

	if len(r.options.Domain) > 0 {
		domainsReader := strings.NewReader(strings.Join(r.options.Domain, "\n"))
		return r.EnumerateMultipleDomainsWithCtx(ctx, domainsReader, outputs)
	}

	// If we have multiple domains as input,
	if r.options.DomainsFile != "" {
		f, err := os.Open(r.options.DomainsFile)
		if err != nil {
			return err
		}
		err = r.EnumerateMultipleDomainsWithCtx(ctx, f, outputs)
		if closeErr := f.Close(); closeErr != nil {
			gologger.Error().Msgf("Error closing file %s: %s", r.options.DomainsFile, closeErr)
		}
		return err
	}

	// If we have STDIN input, treat it as multiple domains
	if r.options.Stdin {
		return r.EnumerateMultipleDomainsWithCtx(ctx, os.Stdin, outputs)
	}
	return nil
}

// EnumerateMultipleDomains wraps EnumerateMultipleDomainsWithCtx with an empty context
func (r *Runner) EnumerateMultipleDomains(reader io.Reader, writers []io.Writer) error {
	ctx, _ := contextutil.WithValues(context.Background(), contextutil.ContextArg("All"), contextutil.ContextArg(strconv.FormatBool(r.options.All)))
	return r.EnumerateMultipleDomainsWithCtx(ctx, reader, writers)
}

// EnumerateMultipleDomainsWithCtx enumerates at most Threads domains concurrently.
// Completed domains are written together; domain output order is unspecified.
func (r *Runner) EnumerateMultipleDomainsWithCtx(ctx context.Context, reader io.Reader, writers []io.Writer) (err error) {
	if r.options.Threads < 0 {
		return errors.New("threads must not be negative")
	}
	// SDK callers historically could leave Threads unset for passive enumeration.

	workers := max(1, r.options.Threads)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	limiter, err := r.passiveAgent.NewRateLimiter(ctx, r.options.RateLimit, r.rateLimit)
	if err != nil {
		return fmt.Errorf("create batch rate limiter: %w", err)
	}
	defer func() {
		if closeErr := limiter.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close batch rate limiter: %w", closeErr))
		}
	}()

	batch := *r
	options := *r.options
	batch.options = &options
	batch.sharedRateLimiter = limiter
	batch.outputMu = &sync.Mutex{}
	batch.domainOutput = true

	if options.RemoveWildcard {
		batch.resolverClient = r.resolverClient.WithConcurrencyLimit(workers)
	}

	if callback := options.ResultCallback; callback != nil {
		options.ResultCallback = func(entry *resolve.HostEntry) {
			batch.outputMu.Lock()
			defer batch.outputMu.Unlock()
			callback(entry)
		}
	}

	var sharedFile *os.File
	defer func() {
		if sharedFile != nil {
			err = errors.Join(err, sharedFile.Close())
		}
	}()

	jobs := make(chan relatedJob)

	var wg sync.WaitGroup
	var firstError error
	var errorOnce sync.Once

	fail := func(err error) {
		errorOnce.Do(func() { firstError = err; cancel() })
	}

	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				if ctx.Err() != nil {
					job.finish()
					return
				}

				worker := batch
				worker.passiveAgent = r.newPassiveAgent()
				worker.relatedTag = job.tag

				_, err := worker.EnumerateSingleDomainWithCtx(ctx, job.domain, writers)
				job.finish()
				if err != nil {
					fail(err)
					return
				}
			}
		}()
	}

	scanner := bufio.NewScanner(reader)
	ip := regexp.MustCompile(`^([0-9\.]+$)`)

	// queue validates a domain's destinations and hands it to a worker. It
	// returns false when the run must stop.
	queue := func(job relatedJob) bool {
		domain := job.domain
		// Validate destinations before spending provider requests. Open the shared
		// output only after the first accepted domain so empty input has no effects.
		if options.OutputFile != "" && sharedFile == nil {
			sharedFile, err = NewOutputWriter(options.JSON).createFile(options.OutputFile, true)
			if err != nil {
				fail(err)
				return false
			}

			writers = append(append([]io.Writer(nil), writers...), sharedFile)
			batch.domainOutput = false
		} else if options.OutputFile == "" && options.OutputDirectory != "" {
			suffix := ".txt"
			if options.JSON {
				suffix = ".json"
			}

			batch.outputMu.Lock()

			file, openErr := NewOutputWriter(options.JSON).createFile(path.Join(options.OutputDirectory, domain+suffix), true)
			if openErr == nil {
				openErr = file.Close()
			}

			batch.outputMu.Unlock()

			if openErr != nil {
				fail(openErr)
				return false
			}
		}

		select {
		case <-ctx.Done():
			return false
		case jobs <- job:
			return true
		}
	}

	if r.related == nil {
		// Stock behaviour: stream the input, one domain at a time.
	stream:
		for ctx.Err() == nil && scanner.Scan() {
			domain := replacer.Replace(preprocessDomain(scanner.Text()))
			if domain == "" || (options.ExcludeIps && ip.MatchString(domain)) {
				continue
			}
			if !queue(relatedJob{domain: domain}) {
				break stream
			}
		}
		if err := scanner.Err(); err != nil {
			fail(fmt.Errorf("read domains: %w", err))
		}
	} else {
		// Related-scope expansion needs every input first, so a domain the
		// user passed is never added a second time as someone's relative.
		var inputs []string
		for ctx.Err() == nil && scanner.Scan() {
			domain := replacer.Replace(preprocessDomain(scanner.Text()))
			if domain == "" || (options.ExcludeIps && ip.MatchString(domain)) {
				continue
			}
			inputs = append(inputs, domain)
		}
		if err := scanner.Err(); err != nil {
			fail(fmt.Errorf("read domains: %w", err))
		}

		expansion := &related{
			client:  newRelatedClient(r.related.key, time.Duration(max(options.Timeout, 1))*time.Second),
			classes: r.related.classes,
			seen:    make(map[string]struct{}, len(inputs)),
		}
		for _, domain := range inputs {
			expansion.seen[strings.ToLower(domain)] = struct{}{}
		}

		// Every domain the user passed is enumerated before any related domain
		// starts, so related domains never compete with the seeds for the
		// sources' rate limits. The related lookups run while the seeds do.
		var seedsDone sync.WaitGroup
		var pending []relatedJob
		for _, domain := range inputs {
			if ctx.Err() != nil {
				break
			}
			seedsDone.Add(1)
			if !queue(relatedJob{domain: domain, done: &seedsDone}) {
				seedsDone.Done()
				break
			}
			if ip.MatchString(domain) {
				continue
			}
			pending = append(pending, expansion.expand(ctx, domain)...)
		}
		waitDone(ctx, &seedsDone)
		for _, job := range pending {
			if !queue(job) {
				break
			}
		}
	}

	close(jobs)
	wg.Wait()

	if firstError != nil {
		return firstError
	}

	return ctx.Err()
}
