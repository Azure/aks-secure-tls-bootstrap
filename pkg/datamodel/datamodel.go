// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package datamodel

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type AzureADTokenClaims struct {
	ClaimNames struct {
		Groups string `json:"groups"`
	} `json:"_claim_names"`
	ClaimSources struct {
		Src1 struct {
			Endpoint string `json:"endpoint"`
		} `json:"src1"`
	} `json:"_claim_sources"`
	Acr               string   `json:"acr"`
	Aio               string   `json:"aio"`
	Amr               []string `json:"amr"`
	AppID             string   `json:"appid"`
	AppIDAcr          string   `json:"appidacr"`
	Azp               string   `json:"azp"`
	Azpacr            string   `json:"azpacr"`
	DeviceID          string   `json:"deviceid"`
	FamilyName        string   `json:"family_name"`
	GivenName         string   `json:"given_name"`
	Groups            []string `json:"groups"`
	HasGroups         bool     `json:"hasgroups"`
	Idp               string   `json:"idp"`
	IPAddr            string   `json:"ipaddr"`
	Name              string   `json:"name"`
	Oid               string   `json:"oid"`
	OnpremSID         string   `json:"onprem_sid"`
	PreferredUsername string   `json:"preferred_username"`
	Puid              string   `json:"puid"`
	Rh                string   `json:"rh"`
	Roles             []string `json:"roles"`
	Scp               string   `json:"scp"`
	Tid               string   `json:"tid"`
	UniqueName        string   `json:"unique_name"`
	Upn               string   `json:"upn"`
	Uti               string   `json:"uti"`
	Ver               string   `json:"ver"`
	Wids              []string `json:"wids"`
	jwt.RegisteredClaims
}

func (c *AzureADTokenClaims) Valid() error {
	if c.AppID == "" {
		return fmt.Errorf("appid claim must be included and non-empty")
	}
	if c.Tid == "" {
		return fmt.Errorf("tid claim must be included and non-empty")
	}
	return c.RegisteredClaims.Valid()
}

type Request struct {
	Nonce      string
	Expiration time.Time
	ResourceID string
	VMID       string
	VMName     string
}

type AttestedData struct {
	LicenseType string `json:"licenseType,omitempty"`
	Nonce       string `json:",omitempty"`
	Plan        struct {
		Name      string `json:"name,omitempty"`
		Product   string `json:"product,omitempty"`
		Publisher string `json:"publisher,omitempty"`
	} `json:",omitempty"`
	SubscriptionID string `json:"subscriptionId"`
	Sku            string `json:"sku,omitempty"`
	Timestamp      struct {
		CreatedOn string `json:"createdOn"`
		ExpiresOn string `json:"expiresOn"`
	} `json:"timestamp"`
	VMID string `json:"vmId"`
}

type KubeletAzureJSON struct {
	ClientID               string `json:"aadClientId"`
	ClientSecret           string `json:"aadClientSecret"`
	TenantID               string `json:"tenantId"`
	UserAssignedIdentityID string `json:"userAssignedIdentityID"`
}

type TokenResponseJSON struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	ExpiresIn        string `json:"expires_in"`
	ExpiresOn        string `json:"expires_on"`
	NotBefore        string `json:"not_before"`
	Resource         string `json:"resource"`
	TokenType        string `json:"token_type"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type ExecCredential struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Spec       struct {
		Cluster struct {
			CertificateAuthorityData string      `json:"certificate-authority-data,omitempty"`
			Config                   interface{} `json:"config,omitempty"`
			InsecureSkipTLSVerify    bool        `json:"insecure-skip-tls-verify,omitempty"`
			ProxyURL                 string      `json:"proxy-url,omitempty"`
			Server                   string      `json:"server,omitempty"`
			TLSServerName            string      `json:"tls-server-name,omitempty"`
		} `json:"cluster,omitempty"`
		Interactive bool `json:"interactive,omitempty"`
	} `json:"spec,omitempty"`
	Status struct {
		ClientCertificateData string `json:"clientCertificateData,omitempty"`
		ClientKeyData         string `json:"clientKeyData,omitempty"`
		ExpirationTimestamp   string `json:"expirationTimestamp,omitempty"`
		Token                 string `json:"token,omitempty"`
	} `json:"status,omitempty"`
}

type VmssInstanceData struct {
	Compute struct {
		AzEnvironment    string `json:"azEnvironment"`
		CustomData       string `json:"customData"`
		EvictionPolicy   string `json:"evictionPolicy"`
		ExtendedLocation struct {
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"extendedLocation"`
		IsHostCompatibilityLayerVM string `json:"isHostCompatibilityLayerVm"`
		LicenseType                string `json:"licenseType"`
		Location                   string `json:"location"`
		Name                       string `json:"name"`
		Offer                      string `json:"offer"`
		OsProfile                  struct {
			AdminUsername                 string `json:"adminUsername"`
			ComputerName                  string `json:"computerName"`
			DisablePasswordAuthentication string `json:"disablePasswordAuthentication"`
		} `json:"osProfile"`
		OsType           string `json:"osType"`
		PlacementGroupID string `json:"placementGroupId"`
		Plan             struct {
			Name      string `json:"name"`
			Product   string `json:"product"`
			Publisher string `json:"publisher"`
		} `json:"plan"`
		PlatformFaultDomain  string        `json:"platformFaultDomain"`
		PlatformUpdateDomain string        `json:"platformUpdateDomain"`
		Priority             string        `json:"priority"`
		Provider             string        `json:"provider"`
		PublicKeys           []interface{} `json:"publicKeys"`
		Publisher            string        `json:"publisher"`
		ResourceGroupName    string        `json:"resourceGroupName"`
		ResourceID           string        `json:"resourceId"`
		SecurityProfile      struct {
			SecureBootEnabled string `json:"secureBootEnabled"`
			VirtualTpmEnabled string `json:"virtualTpmEnabled"`
		} `json:"securityProfile"`
		Sku            string `json:"sku"`
		StorageProfile struct {
			DataDisks []struct {
				BytesPerSecondThrottle string `json:"bytesPerSecondThrottle"`
				Caching                string `json:"caching"`
				CreateOption           string `json:"createOption"`
				DiskCapacityBytes      string `json:"diskCapacityBytes"`
				DiskSizeGB             string `json:"diskSizeGB"`
				Image                  struct {
					URI string `json:"uri"`
				} `json:"image"`
				IsSharedDisk string `json:"isSharedDisk"`
				IsUltraDisk  string `json:"isUltraDisk"`
				Lun          string `json:"lun"`
				ManagedDisk  struct {
					ID                 string `json:"id"`
					StorageAccountType string `json:"storageAccountType"`
				} `json:"managedDisk"`
				Name                 string `json:"name"`
				OpsPerSecondThrottle string `json:"opsPerSecondThrottle"`
				Vhd                  struct {
					URI string `json:"uri"`
				} `json:"vhd"`
				WriteAcceleratorEnabled string `json:"writeAcceleratorEnabled"`
			} `json:"dataDisks"`
			ImageReference struct {
				ID        string `json:"id"`
				Offer     string `json:"offer"`
				Publisher string `json:"publisher"`
				Sku       string `json:"sku"`
				Version   string `json:"version"`
			} `json:"imageReference"`
			OsDisk struct {
				Caching          string `json:"caching"`
				CreateOption     string `json:"createOption"`
				DiffDiskSettings struct {
					Option string `json:"option"`
				} `json:"diffDiskSettings"`
				DiskSizeGB         string `json:"diskSizeGB"`
				EncryptionSettings struct {
					Enabled string `json:"enabled"`
				} `json:"encryptionSettings"`
				Image struct {
					URI string `json:"uri"`
				} `json:"image"`
				ManagedDisk struct {
					ID                 string `json:"id"`
					StorageAccountType string `json:"storageAccountType"`
				} `json:"managedDisk"`
				Name   string `json:"name"`
				OsType string `json:"osType"`
				Vhd    struct {
					URI string `json:"uri"`
				} `json:"vhd"`
				WriteAcceleratorEnabled string `json:"writeAcceleratorEnabled"`
			} `json:"osDisk"`
			ResourceDisk struct {
				Size string `json:"size"`
			} `json:"resourceDisk"`
		} `json:"storageProfile"`
		SubscriptionID string `json:"subscriptionId"`
		Tags           string `json:"tags"`
		TagsList       []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"tagsList"`
		UserData               string `json:"userData"`
		Version                string `json:"version"`
		VirtualMachineScaleSet struct {
			ID string `json:"id"`
		} `json:"virtualMachineScaleSet"`
		VMID           string `json:"vmId"`
		VMScaleSetName string `json:"vmScaleSetName"`
		VMSize         string `json:"vmSize"`
		Zone           string `json:"zone"`
	} `json:"compute"`
	Network struct {
		Interface []struct {
			Ipv4 struct {
				IPAddress []struct {
					PrivateIPAddress string `json:"privateIpAddress"`
					PublicIPAddress  string `json:"publicIpAddress"`
				} `json:"ipAddress"`
				Subnet []struct {
					Address string `json:"address"`
					Prefix  string `json:"prefix"`
				} `json:"subnet"`
			} `json:"ipv4"`
			Ipv6 struct {
				IPAddress []struct {
					PrivateIPAddress string `json:"privateIpAddress"`
				} `json:"ipAddress"`
			} `json:"ipv6"`
			MacAddress string `json:"macAddress"`
		} `json:"interface"`
	} `json:"network"`
}

type VmssAttestedData struct {
	Encoding  string `json:"encoding"`
	Signature string `json:"signature"`
}
