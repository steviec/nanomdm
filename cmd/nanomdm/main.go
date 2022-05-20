package main

import (
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	stdlog "log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/micromdm/nanomdm/certverify"
	"github.com/micromdm/nanomdm/cmd/cli"
	mdmhttp "github.com/micromdm/nanomdm/http"
	"github.com/micromdm/nanomdm/log/stdlogfmt"
	"github.com/micromdm/nanomdm/push/buford"
	pushsvc "github.com/micromdm/nanomdm/push/service"
	"github.com/micromdm/nanomdm/service"
	"github.com/micromdm/nanomdm/service/certauth"
	"github.com/micromdm/nanomdm/service/dump"
	"github.com/micromdm/nanomdm/service/microwebhook"
	"github.com/micromdm/nanomdm/service/multi"
	"github.com/micromdm/nanomdm/service/nanomdm"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/awslabs/aws-lambda-go-api-proxy/httpadapter"
)

// overridden by -ldflags -X
var version = "unknown"

const (
	endpointMDM     = "/mdm"
	endpointCheckin = "/checkin"

	endpointAPIPushCert  = "/v1/pushcert"
	endpointAPIPush      = "/v1/push/"
	endpointAPIEnqueue   = "/v1/enqueue/"
	endpointAPIMigration = "/migration"
	endpointAPIVersion   = "/version"
)

func main() {
	cliStorage := cli.NewStorage()
	flag.Var(&cliStorage.Storage, "storage", "name of storage backend")
	flag.Var(&cliStorage.DSN, "dsn", "data source name (e.g. connection string or path)")
	flag.Var(&cliStorage.Options, "storage-options", "storage backend options")
	var (
		flListen     = flag.String("listen", ":9000", "HTTP listen address")
		flAPIKey     = flag.String("api", "", "API key for API endpoints")
		flVersion    = flag.Bool("version", false, "print version")
		flRootsPath  = flag.String("ca", "", "path to CA cert for verification")
		flInlineCert = flag.String("inline-cert", "", "path to CA cert for verification")
		flWebhook    = flag.String("webhook-url", "", "URL to send requests to")
		flCertHeader = flag.String("cert-header", "", "HTTP header containing URL-escaped TLS client certificate")
		flDebug      = flag.Bool("debug", false, "log debug messages")
		flDump       = flag.Bool("dump", false, "dump MDM requests and responses to stdout")
		flDisableMDM = flag.Bool("disable-mdm", false, "disable MDM HTTP endpoint")
		flCheckin    = flag.Bool("checkin", false, "enable separate HTTP endpoint for MDM check-ins")
		flMigration  = flag.Bool("migration", false, "HTTP endpoint for enrollment migrations")
		flRetro      = flag.Bool("retro", false, "Allow retroactive certificate-authorization association")
		flDMURLPfx   = flag.String("dm", "", "URL to send Declarative Management requests to")
		flLambda     = flag.Bool("lambda", false, "Run using a lambda")
	)

	var err error

	// doing this before flag.Parse() to allow CLI flags to take precedence
	err = SetFlagsFromEnvironment("MDM")
	if err != nil {
		stdlog.Fatal(err)
	}

	flag.Parse()

	if *flVersion {
		fmt.Println(version)
		return
	}

	if *flDisableMDM && *flAPIKey == "" {
		stdlog.Fatal("nothing for server to do")
	}

	logger := stdlogfmt.New(stdlog.Default(), *flDebug)

	if *flRootsPath == "" && *flInlineCert == "" {
		stdlog.Fatal("must supply CA cert path flag or provide the CA cert inline")
	}

	var caPEM []byte
	if *flRootsPath != "" {
		caPEM, err = ioutil.ReadFile(*flRootsPath)
	} else {
		caPEM = []byte(*flInlineCert)
	}

	if err != nil {
		stdlog.Fatal(err)
	}
	verifier, err := certverify.NewPoolVerifier(caPEM, x509.ExtKeyUsageClientAuth)
	if err != nil {
		stdlog.Fatal(err)
	}

	mdmStorage, err := cliStorage.Parse(logger)
	if err != nil {
		stdlog.Fatal(err)
	}

	// create 'core' MDM service
	nanoOpts := []nanomdm.Option{nanomdm.WithLogger(logger.With("service", "nanomdm"))}
	if *flDMURLPfx != "" {
		logger.Debug("msg", "declarative management setup", "url", *flDMURLPfx)
		dm := nanomdm.NewDeclarativeManagementHTTPCaller(*flDMURLPfx)
		nanoOpts = append(nanoOpts, nanomdm.WithDeclarativeManagement(dm))
	}
	nano := nanomdm.New(mdmStorage, nanoOpts...)

	mux := http.NewServeMux()

	if !*flDisableMDM {
		var mdmService service.CheckinAndCommandService = nano
		if *flWebhook != "" {
			webhookService := microwebhook.New(*flWebhook, mdmStorage)
			mdmService = multi.New(logger.With("service", "multi"), mdmService, webhookService)
		}
		certAuthOpts := []certauth.Option{certauth.WithLogger(logger.With("service", "certauth"))}
		if *flRetro {
			certAuthOpts = append(certAuthOpts, certauth.WithAllowRetroactive())
		}
		mdmService = certauth.New(mdmService, mdmStorage, certAuthOpts...)
		if *flDump {
			mdmService = dump.New(mdmService, os.Stdout)
		}

		// register 'core' MDM HTTP handler
		var mdmHandler http.Handler
		if *flCheckin {
			// if we use the check-in handler then only handle commands
			mdmHandler = mdmhttp.CommandAndReportResultsHandler(mdmService, logger.With("handler", "command"))
		} else {
			// if we don't use a check-in handler then do both
			mdmHandler = mdmhttp.CheckinAndCommandHandler(mdmService, logger.With("handler", "checkin-command"))
		}
		mdmHandler = mdmhttp.CertVerifyMiddleware(mdmHandler, verifier, logger.With("handler", "cert-verify"))
		if *flCertHeader != "" {
			mdmHandler = mdmhttp.CertExtractPEMHeaderMiddleware(mdmHandler, *flCertHeader, logger.With("handler", "cert-extract"))
		} else {
			mdmHandler = mdmhttp.CertExtractMdmSignatureMiddleware(mdmHandler, logger.With("handler", "cert-extract"))
		}
		mux.Handle(endpointMDM, mdmHandler)

		if *flCheckin {
			// if we specified a separate check-in handler, set it up
			var checkinHandler http.Handler
			checkinHandler = mdmhttp.CheckinHandler(mdmService, logger.With("handler", "checkin"))
			checkinHandler = mdmhttp.CertVerifyMiddleware(checkinHandler, verifier, logger.With("handler", "cert-verify"))
			if *flCertHeader != "" {
				checkinHandler = mdmhttp.CertExtractPEMHeaderMiddleware(checkinHandler, *flCertHeader, logger.With("handler", "cert-extract"))
			} else {
				checkinHandler = mdmhttp.CertExtractMdmSignatureMiddleware(checkinHandler, logger.With("handler", "cert-extract"))
			}
			mux.Handle(endpointCheckin, checkinHandler)
		}
	}

	if *flAPIKey != "" {
		const apiUsername = "nanomdm"

		// create our push provider and push service
		pushProviderFactory := buford.NewPushProviderFactory()
		pushService := pushsvc.New(mdmStorage, mdmStorage, pushProviderFactory, logger.With("service", "push"))

		// register API handler for push cert storage/upload.
		var pushCertHandler http.Handler
		pushCertHandler = mdmhttp.StorePushCertHandler(mdmStorage, logger.With("handler", "store-cert"))
		pushCertHandler = mdmhttp.BasicAuthMiddleware(pushCertHandler, apiUsername, *flAPIKey, "nanomdm")
		mux.Handle(endpointAPIPushCert, pushCertHandler)

		// register API handler for push notifications.
		// we strip the prefix to use the path as an id.
		var pushHandler http.Handler
		pushHandler = mdmhttp.PushHandler(pushService, logger.With("handler", "push"))
		pushHandler = http.StripPrefix(endpointAPIPush, pushHandler)
		pushHandler = mdmhttp.BasicAuthMiddleware(pushHandler, apiUsername, *flAPIKey, "nanomdm")
		mux.Handle(endpointAPIPush, pushHandler)

		// register API handler for new command queueing.
		// we strip the prefix to use the path as an id.
		var enqueueHandler http.Handler
		enqueueHandler = mdmhttp.RawCommandEnqueueHandler(mdmStorage, pushService, logger.With("handler", "enqueue"))
		enqueueHandler = http.StripPrefix(endpointAPIEnqueue, enqueueHandler)
		enqueueHandler = mdmhttp.BasicAuthMiddleware(enqueueHandler, apiUsername, *flAPIKey, "nanomdm")
		mux.Handle(endpointAPIEnqueue, enqueueHandler)

		if *flMigration {
			// setup a "migration" handler that takes Check-In messages
			// without bothering with certificate auth or other
			// middleware.
			//
			// if the source MDM can put together enough of an
			// authenticate and tokenupdate message to effectively
			// generate "enrollments" then this effively allows us to
			// migrate MDM enrollments between servers.
			var migHandler http.Handler
			migHandler = mdmhttp.CheckinHandler(nano, logger.With("handler", "migration"))
			migHandler = mdmhttp.BasicAuthMiddleware(migHandler, apiUsername, *flAPIKey, "nanomdm")
			mux.Handle(endpointAPIMigration, migHandler)
		}
	}

	mux.HandleFunc(endpointAPIVersion, mdmhttp.VersionHandler(version))

	muxWithTraceLogging := mdmhttp.TraceLoggingMiddleware(mux, logger.With("handler", "log"), newTraceID)

	rand.Seed(time.Now().UnixNano())

	if *flLambda {
		// Proxies requests from the AWS API Gateway to go's http handlers
		// https://github.com/awslabs/aws-lambda-go-api-proxy
		lambda.Start(httpadapter.New(muxWithTraceLogging).ProxyWithContext)
	} else {
		logger.Info("msg", "starting server", "listen", *flListen)
		err = http.ListenAndServe(*flListen, muxWithTraceLogging)
		logs := []interface{}{"msg", "server shutdown"}
		if err != nil {
			logs = append(logs, "err", err)
		}
		logger.Info(logs...)
	}
}

// newTraceID generates a new HTTP trace ID for context logging.
// Currently this just makes a random string. This would be better
// served by e.g. https://github.com/oklog/ulid or something like
// https://opentelemetry.io/ someday.
func newTraceID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// In order to make nanomdm work within various contexts, we should allow configuration
// to be passed in via environment variables. See https://12factor.net/config.
// There are LOTS of flag parsing libraries that support doing this, but to avoid additional
// layers of abstraction let's just parse ENV variables using the built-in flag library.
//
// Hat tip: https://utz.us/posts/go-flags-from-environment/
func SetFlagsFromEnvironment(prefix string) (err error) {
	flag.VisitAll(func(f *flag.Flag) {
		name := prefix + "_" + strings.ToUpper(strings.Replace(f.Name, "-", "_", -1))
		if value, ok := os.LookupEnv(name); ok {
			err2 := flag.Set(f.Name, value)
			if err2 != nil {
				err = fmt.Errorf("failed setting flag from environment: %w", err2)
			}
		}
	})

	return
}
