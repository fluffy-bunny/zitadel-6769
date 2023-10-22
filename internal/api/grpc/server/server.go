package server

import (
	"crypto/tls"

	"github.com/gorilla/mux"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	internal_authz "github.com/zitadel/zitadel/internal/api/authz"
	grpc_api "github.com/zitadel/zitadel/internal/api/grpc"
	"github.com/zitadel/zitadel/internal/api/grpc/server/middleware"
	http_mw "github.com/zitadel/zitadel/internal/api/http/middleware"
	"github.com/zitadel/zitadel/internal/logstore"
	"github.com/zitadel/zitadel/internal/logstore/record"
	"github.com/zitadel/zitadel/internal/query"
	"github.com/zitadel/zitadel/internal/telemetry/metrics"
	system_pb "github.com/zitadel/zitadel/pkg/grpc/system"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

type NewServerOptions struct {
	EnableReflection  bool
	Port              uint16
	Router            *mux.Router
	Queries           *query.Queries
	Verifier          *internal_authz.TokenVerifier
	AuthZ             internal_authz.Config
	TLSConfig         *tls.Config
	HTTP2HostName     string
	HTTP1HostName     string
	AccessInterceptor *http_mw.AccessInterceptor
}
type Server interface {
	RegisterServer(*grpc.Server)
	RegisterGateway() RegisterGatewayFunc
	AppName() string
	MethodPrefix() string
	AuthMethods() internal_authz.MethodMapping
}

// WithGatewayPrefix extends the server interface with a prefix for the grpc gateway
//
// it's used for the System, Admin, Mgmt and Auth API
type WithGatewayPrefix interface {
	Server
	GatewayPathPrefix() string
}

func CreateServer(
	verifier *internal_authz.TokenVerifier,
	authConfig internal_authz.Config,
	queries *query.Queries,
	hostHeaderName string,
	tlsConfig *tls.Config,
	accessSvc *logstore.Service[*record.AccessLog],
) *grpc.Server {
	metricTypes := []metrics.MetricType{metrics.MetricTypeTotalCount, metrics.MetricTypeRequestCount, metrics.MetricTypeStatusCode}
	serverOptions := []grpc.ServerOption{
		grpc.UnaryInterceptor(
			grpc_middleware.ChainUnaryServer(
				middleware.CallDurationHandler(),
				middleware.DefaultTracingServer(),
				middleware.MetricsHandler(metricTypes, grpc_api.Probes...),
				middleware.NoCacheInterceptor(),
				middleware.InstanceInterceptor(queries, hostHeaderName, system_pb.SystemService_ServiceDesc.ServiceName, healthpb.Health_ServiceDesc.ServiceName),
				middleware.AccessStorageInterceptor(accessSvc),
				middleware.ErrorHandler(),
				middleware.AuthorizationInterceptor(verifier, authConfig),
				middleware.QuotaExhaustedInterceptor(accessSvc, system_pb.SystemService_ServiceDesc.ServiceName),
				middleware.TranslationHandler(),
				middleware.ValidationHandler(),
				middleware.ServiceHandler(),
			),
		),
	}
	if tlsConfig != nil {
		serverOptions = append(serverOptions, grpc.Creds(credentials.NewTLS(tlsConfig)))
	}
	return grpc.NewServer(serverOptions...)
}
