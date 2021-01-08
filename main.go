package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog"

	"github.com/infobloxopen/infoblox-go-client"
	"github.com/jetstack/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/acme/webhook/cmd"
	apis "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName,
		&customDNSProviderSolver{},
	)
}

// customDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/jetstack/cert-manager/pkg/acme/webhook.Solver`
// interface.
type customDNSProviderSolver struct {
	// If a Kubernetes 'clientset' is needed, you must:
	// 1. uncomment the additional `client` field in this structure below
	// 2. uncomment the "k8s.io/client-go/kubernetes" import at the top of the file
	// 3. uncomment the relevant code in the Initialize method below
	// 4. ensure your webhook's service account has the required RBAC role
	//    assigned to it for interacting with the Kubernetes APIs you need.
	client *kubernetes.Clientset
}

// customDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type customDNSProviderConfig struct {
	// Change the two fields below according to the format of the configuration
	// to be decoded.
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.
	Host              string                 `json:"host"`
	Port              string                 `json:"port"`
	Version           string                 `json:"version"`
	SSLVerify         bool                   `json:"sslVerify"`
	UsernameSecretRef apis.SecretKeySelector `json:"userNameSecretRef"`
	PasswordSecretRef apis.SecretKeySelector `json:"passwordSecretRef"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *customDNSProviderSolver) Name() string {
	return "infoblox-solver"
}

func (c *customDNSProviderSolver) getDomainAndEntry(ch *v1alpha1.ChallengeRequest) (string, string) {
	// Both ch.ResolvedZone and ch.ResolvedFQDN end with a dot: '.'
	entry := strings.TrimSuffix(ch.ResolvedFQDN, ch.ResolvedZone)
	entry = strings.TrimSuffix(entry, ".")
	domain := strings.TrimSuffix(ch.ResolvedZone, ".")
	return entry, domain
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *customDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	klog.Infof("Decoded configuration %v", cfg)

	entry, domain := c.getDomainAndEntry(ch)
	klog.Infof("present for entry=%s, domain=%s", entry, domain)

	klog.Infof("Presenting txt record: %v %v", ch.ResolvedFQDN, ch.ResolvedZone)

	// Code that sets a record in the DNS provider's console

	client, err := c.getClient(&cfg, ch.ResourceNamespace)

	if err != nil {
		klog.Errorf("unable to get client: %s", err)
		return err
	}

	rt := ibclient.NewRecordTXT(ibclient.RecordTXT{Name: entry})

	var records []ibclient.RecordTXT
	err = client.GetObject(rt, "", &records)
	if err != nil {
		return err
	}

	for _, rec := range records {
		if rec.Text == ch.Key {
			return nil
		}
	}

	rt = ibclient.NewRecordTXT(ibclient.RecordTXT{
		Name: entry,
		Text: ch.Key})

	ref, err := client.CreateObject(rt)
	if err != nil {
		return err
	}

	klog.Infof("INFOBLOX: created TXT record %v, %s -> %s", rt, ch.Key, ref)

	return nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *customDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	klog.Infof("Decoded configuration %v", cfg)

	entry, domain := c.getDomainAndEntry(ch)
	klog.Infof("present for entry=%s, domain=%s", entry, domain)

	// Code that deletes a record from the DNS provider's console

	client, err := c.getClient(&cfg, ch.ResourceNamespace)

	if err != nil {
		klog.Errorf("unable to get client: %s", err)
		return err
	}

	rt := ibclient.NewRecordTXT(ibclient.RecordTXT{Name: entry})

	var records []ibclient.RecordTXT
	err = client.GetObject(rt, "", &records)
	if err != nil {
		return err
	}

	var ref string
	for _, rec := range records {
		if rec.Text == ch.Key {
			ref = rec.Ref
			break
		}
	}

	if len(ref) == 0 {
		return nil
	}

	_, err = client.DeleteObject(ref)
	if err != nil {
		return err
	}

	klog.Infof("INFOBLOX: deleting TXT record %s, %s -> %s", domain, ch.Key, ref)

	return nil
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (c *customDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	///// UNCOMMENT THE BELOW CODE TO MAKE A KUBERNETES CLIENTSET AVAILABLE TO
	///// YOUR CUSTOM DNS PROVIDER

	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	c.client = cl

	///// END OF CODE TO MAKE KUBERNETES CLIENTSET AVAILABLE
	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (customDNSProviderConfig, error) {
	cfg := customDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}

func (c *customDNSProviderSolver) getClient(cfg *customDNSProviderConfig, namespace string) (ibclient.IBConnector, error) {

	userName, err := c.getSecretData(cfg.UsernameSecretRef, namespace)
	if err != nil {
		return nil, err
	}

	password, err := c.getSecretData(cfg.PasswordSecretRef, namespace)
	if err != nil {
		return nil, err
	}

	hostConfig := ibclient.HostConfig{
		Host:     cfg.Host,
		Port:     cfg.Port,
		Username: string(userName),
		Password: string(password),
		Version:  cfg.Version,
	}

	httpPoolConnections := 10
	httpRequestTimeout := 60

	transportConfig := ibclient.NewTransportConfig(
		strconv.FormatBool(cfg.SSLVerify),
		httpRequestTimeout,
		httpPoolConnections,
	)

	requestBuilder := &ibclient.WapiRequestBuilder{}
	requestor := &ibclient.WapiHttpRequestor{}

	client, err := ibclient.NewConnector(hostConfig, transportConfig, requestBuilder, requestor)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func (c *customDNSProviderSolver) getSecretData(selector apis.SecretKeySelector, ns string) ([]byte, error) {

	secret, err := c.client.CoreV1().Secrets(ns).Get(context.Background(), selector.Name, metav1.GetOptions{})

	if err != nil {
		return nil, errors.Wrapf(err, "failed to load secret %q", ns+"/"+selector.Name)
	}

	if data, ok := secret.Data[selector.Key]; ok {
		return data, nil
	}

	return nil, errors.Errorf("no key %q in secret %q", selector.Key, ns+"/"+selector.Name)
}
