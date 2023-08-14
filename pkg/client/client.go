package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"

	"github.com/Azure/aks-tls-bootstrap-client/pkg/datamodel"
	pb "github.com/Azure/aks-tls-bootstrap-client/pkg/proto"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/oauth"
)

type TLSBootstrapClient interface {
	GetBootstrapToken() (string, error)
}

func NewTLSBootstrapClient(logger *logrus.Logger, clientID, nextProto string) TLSBootstrapClient {
	imdsClient := NewImdsClient(logger)
	aadClient := NewAadClient(logger)

	return &tlsBootstrapClientImpl{
		logger:     logger,
		imdsClient: imdsClient,
		aadClient:  aadClient,
		clientID:   clientID,
		nextProto:  nextProto,
	}
}

type tlsBootstrapClientImpl struct {
	logger     *logrus.Logger
	imdsClient ImdsClient
	aadClient  AadClient
	clientID   string
	nextProto  string
}

func (c *tlsBootstrapClientImpl) GetBootstrapToken() (string, error) {
	c.logger.Info("retrieving auth token")

	execCredential, err := loadExecCredential(c.logger)
	if err != nil {
		return "", err
	}

	pemCAs, err := base64.StdEncoding.DecodeString(execCredential.Spec.Cluster.CertificateAuthorityData)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64 cluster certificates: %w", err)
	}

	tlsConfig, err := getTLSConfig(pemCAs, c.nextProto, execCredential.Spec.Cluster.InsecureSkipTLSVerify)
	if err != nil {
		return "", fmt.Errorf("failed to get TLS config: %w", err)
	}

	azureConfig, err := loadAzureJSON()
	if err != nil {
		return "", fmt.Errorf("failed to parse azure config from azure.json: %w", err)
	}

	token, err := c.getAuthToken(c.clientID, azureConfig)
	if err != nil {
		return "", err
	}

	server, err := getServerURL(execCredential)
	if err != nil {
		return "", err
	}

	conn, err := grpc.Dial(server,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithPerRPCCredentials(oauth.NewOauthAccess(&oauth2.Token{
			AccessToken: token,
		})),
	)
	if err != nil {
		return "", fmt.Errorf("failed to connect to %s: %w", execCredential.Spec.Cluster.Server, err)
	}
	defer conn.Close()

	pbClient := pb.NewAKSBootstrapTokenRequestClient(conn)

	c.logger.Info("retrieving IMDS instance data")
	instanceData, err := c.imdsClient.GetInstanceData(baseImdsURL)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve instance metadata from IMDS: %w", err)
	}

	c.logger.Infof("retrieving nonce from TLS bootstrap token server at %s", server)
	nonceRequest := pb.NonceRequest{
		ResourceId: instanceData.Compute.ResourceID,
	}
	nonce, err := pbClient.GetNonce(context.Background(), &nonceRequest)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve a nonce: %w", err)
	}
	c.logger.Infof("nonce reply is %s", nonce.Nonce)

	c.logger.Info("retrieving IMDS attested data")
	attestedData, err := c.imdsClient.GetAttestedData(baseImdsURL, nonce.Nonce)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve attested data from IMDS: %w", err)
	}

	c.logger.Info("retrieving bootstrap token from TLS bootstrap token server")
	tokenRequest := pb.TokenRequest{
		ResourceId:   instanceData.Compute.ResourceID,
		Nonce:        nonce.Nonce,
		AttestedData: attestedData.Signature,
	}
	tokenReply, err := pbClient.GetToken(context.Background(), &tokenRequest)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve a token: %w", err)
	}
	c.logger.Info("received token reply")

	execCredential.APIVersion = "client.authentication.k8s.io/v1"
	execCredential.Kind = "ExecCredential"
	execCredential.Status.Token = tokenReply.Token
	execCredential.Status.ExpirationTimestamp = tokenReply.Expiration

	execCredentialBytes, err := json.Marshal(execCredential)
	if err != nil {
		return "", fmt.Errorf("failed to marshal execCredential")
	}
	return string(execCredentialBytes), nil
}

func loadExecCredential(logger *logrus.Logger) (*datamodel.ExecCredential, error) {
	logger.WithField(kubernetesExecInfoVarName, os.Getenv(kubernetesExecInfoVarName)).Debugf("parsing %s variable", kubernetesExecInfoVarName)
	kubernetesExecInfoVar := os.Getenv(kubernetesExecInfoVarName)
	if kubernetesExecInfoVar == "" {
		return nil, fmt.Errorf("%s variable not found", kubernetesExecInfoVarName)
	}

	execCredential := &datamodel.ExecCredential{}
	if err := json.Unmarshal([]byte(kubernetesExecInfoVar), execCredential); err != nil {
		return nil, err
	}

	return execCredential, nil
}

func getServerURL(execCredential *datamodel.ExecCredential) (string, error) {
	serverURL, err := url.Parse(execCredential.Spec.Cluster.Server)
	if err != nil {
		return "", fmt.Errorf("failed to parse server URL: %w", err)
	}
	server := serverURL.Hostname() + ":" + serverURL.Port()
	return server, nil
}

func getTLSConfig(pemCAs []byte, nextProto string, insecureSkipVerify bool) (*tls.Config, error) {
	tlsRootStore := x509.NewCertPool()
	ok := tlsRootStore.AppendCertsFromPEM(pemCAs)
	if !ok {
		return nil, fmt.Errorf("failed to load cluster root CA(s)")
	}

	//nolint: gosec // ignore tls min version for now
	tlsConfig := &tls.Config{
		RootCAs: tlsRootStore,
		// TODO(cameissner): fix me
		// MinVersion: tls.VersionTLS13,
		InsecureSkipVerify: insecureSkipVerify,
	}
	if nextProto != "" {
		tlsConfig.NextProtos = []string{nextProto, "h2"}
	}

	return tlsConfig, nil
}
