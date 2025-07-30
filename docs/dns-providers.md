# DNS Providers for ACME SSL Certificates

This document provides comprehensive information about configuring DNS providers for automatic SSL certificate provisioning using ACME DNS-01 challenges in the Gateway.

## Overview

The Gateway supports automatic SSL certificate generation using ACME (Let's Encrypt) with DNS-01 challenges. This method requires creating TXT records in your DNS zone to prove domain ownership. The Gateway includes built-in support for multiple DNS providers with an extensible architecture for adding new providers.

## Supported DNS Providers

### 1. CloudFlare

CloudFlare is a popular DNS provider with an excellent API that supports fast propagation.

#### Required Environment Variables

```bash
# CloudFlare API Token (recommended) - create a token with Zone:Edit permissions
CF_API_TOKEN=your_cloudflare_api_token

# CloudFlare Zone ID - found in your domain's overview page
CF_ZONE_ID=your_zone_id
```

#### Configuration Steps

1. **Create API Token**:
   - Go to CloudFlare Dashboard → My Profile → API Tokens
   - Click "Create Token"
   - Use "Custom token" template
   - Permissions: Zone:Edit, Zone:Read
   - Zone Resources: Include specific zone or all zones

2. **Find Zone ID**:
   - Go to your domain in CloudFlare Dashboard
   - Zone ID is shown in the right sidebar under "API"

3. **Set Environment Variables**:
   ```bash
   export CF_API_TOKEN=your_token_here
   export CF_ZONE_ID=your_zone_id_here
   ```

#### Features
- **Propagation Time**: ~60 seconds
- **Global Anycast**: Fast worldwide propagation
- **Rate Limits**: Very generous API limits
- **Wildcard Support**: Full support for wildcard certificates

---

### 2. AWS Route53

Amazon Route53 is AWS's DNS service with excellent integration for AWS infrastructure.

#### Required Environment Variables

```bash
# AWS Access Key ID
AWS_ACCESS_KEY_ID=your_aws_access_key

# AWS Secret Access Key  
AWS_SECRET_ACCESS_KEY=your_aws_secret_key

# AWS Region (optional, defaults to us-east-1)
AWS_REGION=us-east-1

# AWS Hosted Zone ID (optional, will auto-discover if not provided)
AWS_HOSTED_ZONE_ID=your_hosted_zone_id
```

#### Configuration Steps

1. **Create IAM User**:
   - Go to AWS Console → IAM → Users
   - Create new user with programmatic access
   - Attach policy: `Route53FullAccess` or custom policy with required permissions

2. **Required IAM Permissions**:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "route53:ListHostedZones",
           "route53:GetChange",
           "route53:ChangeResourceRecordSets"
         ],
         "Resource": "*"
       }
     ]
   }
   ```

3. **Set Environment Variables**:
   ```bash
   export AWS_ACCESS_KEY_ID=your_access_key
   export AWS_SECRET_ACCESS_KEY=your_secret_key
   export AWS_REGION=us-east-1
   ```

#### Features
- **Propagation Time**: ~120-180 seconds
- **Global Infrastructure**: AWS's worldwide DNS network
- **Integration**: Perfect for AWS-hosted applications
- **Reliability**: 100% uptime SLA

---

### 3. Azure DNS

Microsoft Azure's DNS service for Azure-hosted domains and applications.

#### Required Environment Variables

```bash
# Azure Subscription ID
AZURE_SUBSCRIPTION_ID=your_subscription_id

# Azure Resource Group containing the DNS zone
AZURE_RESOURCE_GROUP=your_resource_group

# Azure DNS Zone Name
AZURE_DNS_ZONE_NAME=example.com

# Azure Service Principal Credentials
AZURE_CLIENT_ID=your_client_id
AZURE_CLIENT_SECRET=your_client_secret
AZURE_TENANT_ID=your_tenant_id
```

#### Configuration Steps

1. **Create Service Principal**:
   ```bash
   az ad sp create-for-rbac --name "gateway-dns-acme" \
     --role "DNS Zone Contributor" \
     --scopes "/subscriptions/{subscription-id}/resourceGroups/{resource-group}/providers/Microsoft.Network/dnsZones/{zone-name}"
   ```

2. **Alternative: Azure Portal**:
   - Go to Azure Active Directory → App registrations
   - Create new registration
   - Go to Certificates & secrets → Create client secret
   - Assign "DNS Zone Contributor" role to the DNS zone

3. **Set Environment Variables**:
   ```bash
   export AZURE_SUBSCRIPTION_ID=your_subscription_id
   export AZURE_RESOURCE_GROUP=your_resource_group
   export AZURE_DNS_ZONE_NAME=example.com
   export AZURE_CLIENT_ID=your_client_id
   export AZURE_CLIENT_SECRET=your_client_secret
   export AZURE_TENANT_ID=your_tenant_id
   ```

#### Features
- **Propagation Time**: ~120 seconds
- **Integration**: Native Azure integration
- **Security**: Azure AD authentication
- **Scalability**: Enterprise-grade performance

---

### 4. Oracle Cloud DNS

Oracle Cloud Infrastructure's DNS service with global anycast network.

#### Required Environment Variables

```bash
# Oracle Cloud Tenancy OCID
OCI_TENANCY_ID=ocid1.tenancy.oc1..your_tenancy_id

# Oracle Cloud User OCID
OCI_USER_ID=ocid1.user.oc1..your_user_id

# API Key Fingerprint
OCI_FINGERPRINT=your_api_key_fingerprint

# Path to private key file
OCI_PRIVATE_KEY_PATH=/path/to/private_key.pem

# Oracle Cloud Region (optional, defaults to us-ashburn-1)
OCI_REGION=us-ashburn-1

# Compartment OCID
OCI_COMPARTMENT_ID=ocid1.compartment.oc1..your_compartment_id

# DNS Zone Name
OCI_DNS_ZONE_NAME=example.com
```

#### Configuration Steps

1. **Generate API Key Pair**:
   ```bash
   openssl genrsa -out ~/.oci/oci_api_key.pem 2048
   openssl rsa -pubout -in ~/.oci/oci_api_key.pem -out ~/.oci/oci_api_key_public.pem
   chmod 600 ~/.oci/oci_api_key.pem
   ```

2. **Upload Public Key**:
   - Go to OCI Console → Identity → Users → Your User
   - Click "API Keys" → "Add API Key"
   - Upload the public key file
   - Copy the fingerprint

3. **Set Environment Variables**:
   ```bash
   export OCI_TENANCY_ID=ocid1.tenancy.oc1..your_tenancy_id
   export OCI_USER_ID=ocid1.user.oc1..your_user_id
   export OCI_FINGERPRINT=your_fingerprint
   export OCI_PRIVATE_KEY_PATH=/path/to/private_key.pem
   export OCI_COMPARTMENT_ID=ocid1.compartment.oc1..your_compartment_id
   export OCI_DNS_ZONE_NAME=example.com
   ```

#### Features
- **Propagation Time**: ~240 seconds
- **Global Network**: Oracle's worldwide infrastructure
- **Security**: RSA signature-based authentication
- **Performance**: Enterprise-grade DNS resolution

---

## DNS Provider Selection

The Gateway automatically detects and uses available DNS providers based on environment variables. The selection order is:

1. **CloudFlare** (if `CF_API_TOKEN` and `CF_ZONE_ID` are set)
2. **Route53** (if AWS credentials are available)
3. **Azure DNS** (if Azure credentials are available)
4. **Oracle Cloud DNS** (if OCI credentials are available)

If multiple providers are configured, the Gateway will attempt to use them in order until one succeeds.

## Adding New DNS Providers

The Gateway uses an extensible DNS provider architecture that makes it easy to add support for new DNS providers.

### Step 1: Implement the DnsProvider Trait

Create a new file in `crates/gateway-ssl/src/dns/your_provider.rs`:

```rust
use async_trait::async_trait;
use super::provider::{DnsProvider, DnsRecord, DnsError};

pub struct YourProvider {
    // Provider-specific configuration
}

impl YourProvider {
    pub async fn from_env() -> Result<Self, DnsError> {
        // Load configuration from environment variables
    }
}

#[async_trait]
impl DnsProvider for YourProvider {
    fn name(&self) -> &str {
        "Your Provider"
    }
    
    async fn is_available(&self) -> bool {
        // Check if provider is properly configured
    }
    
    async fn create_txt_record(&self, record: &DnsRecord) -> Result<(), DnsError> {
        // Implement TXT record creation via provider's API
    }
    
    async fn delete_txt_record(&self, name: &str) -> Result<(), DnsError> {
        // Implement TXT record deletion via provider's API
    }
    
    fn propagation_delay(&self) -> u64 {
        // Return typical propagation delay in seconds
    }
}
```

### Step 2: Update the Module

Add your provider to `crates/gateway-ssl/src/dns/mod.rs`:

```rust
pub mod your_provider;
```

### Step 3: Update the Factory

Add auto-detection to `DnsProviderFactory::create_available_providers()`:

```rust
// Check Your Provider
if let Ok(provider) = crate::dns::your_provider::YourProvider::from_env().await {
    if provider.is_available().await {
        providers.push(Box::new(provider));
    }
}
```

### Step 4: Add Documentation

Update this file with configuration instructions for your provider.

## Environment Variable Summary

| Provider | Variables | Required |
|----------|-----------|----------|
| **CloudFlare** | `CF_API_TOKEN`, `CF_ZONE_ID` | ✅ Both |
| **Route53** | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | ✅ Both |
|  | `AWS_REGION`, `AWS_HOSTED_ZONE_ID` | ❌ Optional |
| **Azure DNS** | `AZURE_SUBSCRIPTION_ID`, `AZURE_RESOURCE_GROUP` | ✅ Both |
|  | `AZURE_DNS_ZONE_NAME`, `AZURE_CLIENT_ID` | ✅ Both |
|  | `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID` | ✅ Both |
| **Oracle Cloud** | `OCI_TENANCY_ID`, `OCI_USER_ID` | ✅ Both |
|  | `OCI_FINGERPRINT`, `OCI_PRIVATE_KEY_PATH` | ✅ Both |
|  | `OCI_COMPARTMENT_ID`, `OCI_DNS_ZONE_NAME` | ✅ Both |
|  | `OCI_REGION` | ❌ Optional |

## Troubleshooting

### Common Issues

1. **No DNS providers configured**
   - Ensure at least one set of provider credentials is properly set
   - Check environment variable names for typos
   - Verify credentials have correct permissions

2. **DNS record creation fails**
   - Check API credentials and permissions
   - Verify zone/domain configuration
   - Check rate limits and quotas

3. **Certificate provisioning timeout**
   - DNS propagation may take longer than expected
   - Some providers have slower global propagation
   - Increase timeout settings if needed

### Debug Information

Enable debug logging to see detailed DNS provider information:

```bash
export RUST_LOG=debug
```

This will show:
- Available DNS providers
- DNS record creation attempts
- Provider-specific error messages
- Propagation timing information

## Security Considerations

1. **API Credentials**: Store credentials securely, never in code
2. **Permissions**: Use minimal required permissions for each provider
3. **Token Rotation**: Regularly rotate API keys and tokens
4. **Access Logging**: Monitor DNS API usage for unusual activity
5. **Environment Isolation**: Use different credentials for different environments

## Best Practices

1. **Multiple Providers**: Configure multiple providers for redundancy
2. **Monitoring**: Set up alerts for certificate renewal failures
3. **Testing**: Test DNS provider configuration before production
4. **Documentation**: Document which provider is used for each domain
5. **Backup**: Keep backup certificates for critical services