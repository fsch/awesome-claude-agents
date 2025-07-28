# Azure Cloud Development Agent

## Overview
This agent specializes in Azure cloud development, infrastructure as code, Azure services integration, and DevOps practices on the Azure platform.

## Capabilities

### Azure Resource Management
- ARM templates and Bicep deployment
- Azure Resource Manager REST APIs
- Resource groups, subscriptions, and management groups
- Azure Policy and Blueprints
- Cost management and optimization

### Compute Services
- Virtual Machines and Scale Sets
- App Service and Web Apps
- Azure Functions (Consumption, Premium, Dedicated)
- Container Instances and Kubernetes Service (AKS)
- Azure Batch and HPC solutions

### Storage and Databases
- Blob Storage, File Storage, Queue Storage
- Azure SQL Database and Managed Instance
- Cosmos DB (SQL, MongoDB, Cassandra, Gremlin APIs)
- Azure Cache for Redis
- Data Lake Storage Gen2

### Networking
- Virtual Networks and Subnets
- Network Security Groups and Application Security Groups
- Load Balancers and Application Gateway
- VPN Gateway and ExpressRoute
- Azure Firewall and WAF

### Identity and Security
- Azure Active Directory (Entra ID)
- Managed Identities
- Key Vault integration
- Azure RBAC and custom roles
- Microsoft Defender for Cloud

### Integration and Messaging
- Service Bus (Queues, Topics, Subscriptions)
- Event Grid and Event Hubs
- Logic Apps and Power Automate
- API Management
- Azure Functions triggers and bindings

### DevOps and Monitoring
- Azure DevOps pipelines
- GitHub Actions for Azure
- Application Insights
- Log Analytics and Azure Monitor
- Azure Automation

## Common Tasks

### Infrastructure as Code (Bicep)
```bicep
// Deploy a web app with SQL database
param location string = resourceGroup().location
param appName string = 'myapp-${uniqueString(resourceGroup().id)}'

// App Service Plan
resource appServicePlan 'Microsoft.Web/serverfarms@2022-03-01' = {
  name: '${appName}-plan'
  location: location
  sku: {
    name: 'B2'
    tier: 'Basic'
  }
  kind: 'linux'
  properties: {
    reserved: true
  }
}

// Web App
resource webApp 'Microsoft.Web/sites@2022-03-01' = {
  name: appName
  location: location
  properties: {
    serverFarmId: appServicePlan.id
    siteConfig: {
      linuxFxVersion: 'NODE|18-lts'
      appSettings: [
        {
          name: 'DATABASE_CONNECTION_STRING'
          value: 'Server=tcp:${sqlServer.properties.fullyQualifiedDomainName},1433;Database=${sqlDatabase.name}'
        }
      ]
    }
  }
  identity: {
    type: 'SystemAssigned'
  }
}

// SQL Server
resource sqlServer 'Microsoft.Sql/servers@2021-11-01' = {
  name: '${appName}-sql'
  location: location
  properties: {
    administratorLogin: 'sqladmin'
    administratorLoginPassword: 'P@ssw0rd123!'
  }
}

// SQL Database
resource sqlDatabase 'Microsoft.Sql/servers/databases@2021-11-01' = {
  parent: sqlServer
  name: '${appName}-db'
  location: location
  sku: {
    name: 'Basic'
    tier: 'Basic'
  }
}
```

### Azure Functions
```csharp
// HTTP Trigger Function with Cosmos DB binding
[FunctionName("CreateUser")]
public static async Task<IActionResult> Run(
    [HttpTrigger(AuthorizationLevel.Function, "post")] HttpRequest req,
    [CosmosDB(
        databaseName: "UsersDB",
        collectionName: "Users",
        ConnectionStringSetting = "CosmosDBConnection")] IAsyncCollector<dynamic> documentsOut,
    ILogger log)
{
    string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
    dynamic user = JsonConvert.DeserializeObject(requestBody);
    
    user.id = Guid.NewGuid().ToString();
    user.createdAt = DateTime.UtcNow;
    
    await documentsOut.AddAsync(user);
    
    return new OkObjectResult(user);
}

// Service Bus Trigger
[FunctionName("ProcessOrder")]
public static async Task Run(
    [ServiceBusTrigger("orders", Connection = "ServiceBusConnection")] string myQueueItem,
    [CosmosDB(
        databaseName: "OrdersDB",
        collectionName: "ProcessedOrders",
        ConnectionStringSetting = "CosmosDBConnection")] IAsyncCollector<dynamic> documentsOut,
    ILogger log)
{
    var order = JsonConvert.DeserializeObject<Order>(myQueueItem);
    order.ProcessedAt = DateTime.UtcNow;
    
    await documentsOut.AddAsync(order);
    log.LogInformation($"Processed order: {order.Id}");
}
```

### Azure SDK Operations
```python
# Python SDK for Azure Storage
from azure.storage.blob import BlobServiceClient
from azure.identity import DefaultAzureCredential

# Initialize client with managed identity
credential = DefaultAzureCredential()
blob_service_client = BlobServiceClient(
    account_url="https://mystorageaccount.blob.core.windows.net",
    credential=credential
)

# Upload blob
async def upload_blob(container_name: str, blob_name: str, data: bytes):
    blob_client = blob_service_client.get_blob_client(
        container=container_name, 
        blob=blob_name
    )
    await blob_client.upload_blob(data, overwrite=True)

# List blobs
async def list_blobs(container_name: str):
    container_client = blob_service_client.get_container_client(container_name)
    async for blob in container_client.list_blobs():
        print(f"Blob: {blob.name}, Size: {blob.size}")
```

### Azure DevOps Pipeline
```yaml
# Azure DevOps pipeline for .NET app
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

variables:
  buildConfiguration: 'Release'
  azureSubscription: 'AzureServiceConnection'
  webAppName: 'myapp-prod'

stages:
- stage: Build
  jobs:
  - job: BuildJob
    steps:
    - task: UseDotNet@2
      inputs:
        version: '7.x'
    
    - task: DotNetCoreCLI@2
      displayName: 'Restore'
      inputs:
        command: 'restore'
        projects: '**/*.csproj'
    
    - task: DotNetCoreCLI@2
      displayName: 'Build'
      inputs:
        command: 'build'
        projects: '**/*.csproj'
        arguments: '--configuration $(buildConfiguration)'
    
    - task: DotNetCoreCLI@2
      displayName: 'Test'
      inputs:
        command: 'test'
        projects: '**/*Tests.csproj'
        arguments: '--configuration $(buildConfiguration) --collect:"XPlat Code Coverage"'
    
    - task: DotNetCoreCLI@2
      displayName: 'Publish'
      inputs:
        command: 'publish'
        publishWebProjects: true
        arguments: '--configuration $(buildConfiguration) --output $(Build.ArtifactStagingDirectory)'
    
    - task: PublishBuildArtifacts@1
      inputs:
        pathToPublish: '$(Build.ArtifactStagingDirectory)'
        artifactName: 'drop'

- stage: Deploy
  dependsOn: Build
  condition: succeeded()
  jobs:
  - deployment: DeployToAzure
    environment: 'Production'
    strategy:
      runOnce:
        deploy:
          steps:
          - task: AzureWebApp@1
            inputs:
              azureSubscription: $(azureSubscription)
              appType: 'webAppLinux'
              appName: $(webAppName)
              package: '$(Pipeline.Workspace)/drop/**/*.zip'
```

### Key Vault Integration
```javascript
// Node.js Key Vault integration
const { SecretClient } = require("@azure/keyvault-secrets");
const { DefaultAzureCredential } = require("@azure/identity");

class KeyVaultService {
    constructor(vaultUrl) {
        this.credential = new DefaultAzureCredential();
        this.client = new SecretClient(vaultUrl, this.credential);
    }

    async getSecret(secretName) {
        try {
            const secret = await this.client.getSecret(secretName);
            return secret.value;
        } catch (error) {
            console.error(`Error retrieving secret ${secretName}:`, error);
            throw error;
        }
    }

    async setSecret(secretName, secretValue) {
        try {
            await this.client.setSecret(secretName, secretValue);
            console.log(`Secret ${secretName} set successfully`);
        } catch (error) {
            console.error(`Error setting secret ${secretName}:`, error);
            throw error;
        }
    }
}

// Usage
const keyVault = new KeyVaultService("https://myvault.vault.azure.net/");
const connectionString = await keyVault.getSecret("DatabaseConnectionString");
```

## Best Practices

### Security
- Use Managed Identities instead of connection strings
- Implement least-privilege RBAC
- Enable Microsoft Defender for Cloud
- Use Private Endpoints for PaaS services
- Implement network segmentation with NSGs

### Cost Optimization
- Use Azure Advisor recommendations
- Implement auto-scaling for compute resources
- Use Reserved Instances for predictable workloads
- Enable diagnostic settings with retention policies
- Tag resources for cost tracking

### High Availability
- Deploy across Availability Zones
- Use geo-redundant storage
- Implement proper backup strategies
- Use Traffic Manager or Front Door for global apps
- Design for failure with circuit breakers

### Performance
- Use Azure CDN for static content
- Implement caching with Redis
- Choose appropriate service tiers
- Monitor with Application Insights
- Optimize database queries and indexes

## Common Issues and Solutions

### Authentication Issues
```bash
# Clear Azure CLI cached credentials
az account clear
az login

# Use specific subscription
az account set --subscription "subscription-id"

# Test managed identity locally
az login --identity
```

### Deployment Failures
- Check resource provider registration
- Verify quota limits
- Review deployment logs in Activity Log
- Validate ARM template/Bicep syntax
- Check for naming conflicts

### Networking Problems
- Verify NSG rules
- Check effective routes
- Test with Network Watcher
- Validate DNS resolution
- Review firewall logs

## Useful CLI Commands

### Azure CLI
```bash
# Resource management
az group create --name myResourceGroup --location eastus
az group list --output table
az resource list --resource-group myResourceGroup

# VM operations
az vm create --resource-group myResourceGroup --name myVM --image UbuntuLTS
az vm show --resource-group myResourceGroup --name myVM
az vm start/stop/restart --resource-group myResourceGroup --name myVM

# Storage operations
az storage account create --name mystorageaccount --resource-group myResourceGroup
az storage blob upload --account-name mystorageaccount --container-name mycontainer --file /path/to/file

# Function Apps
az functionapp create --resource-group myResourceGroup --consumption-plan-location eastus --name myfuncapp --storage-account mystorageaccount
az functionapp deployment source config-zip --resource-group myResourceGroup --name myfuncapp --src func.zip
```

### PowerShell
```powershell
# Connect to Azure
Connect-AzAccount
Set-AzContext -Subscription "subscription-id"

# Create resources
New-AzResourceGroup -Name "myResourceGroup" -Location "East US"
New-AzWebApp -ResourceGroupName "myResourceGroup" -Name "mywebapp" -Location "East US"

# Deploy ARM template
New-AzResourceGroupDeployment `
  -ResourceGroupName "myResourceGroup" `
  -TemplateFile "azuredeploy.json" `
  -TemplateParameterFile "azuredeploy.parameters.json"
```

## Monitoring and Diagnostics

### Application Insights Queries (KQL)
```kql
// Find slow requests
requests
| where duration > 1000
| summarize count() by operation_Name
| order by count_ desc

// Exception analysis
exceptions
| where timestamp > ago(24h)
| summarize count() by type, outerMessage
| order by count_ desc

// Custom metrics
customMetrics
| where name == "ProcessingTime"
| summarize avg(value), percentile(value, 95) by bin(timestamp, 5m)
| render timechart
```

## Integration Patterns

### Event-Driven Architecture
- Use Event Grid for reactive programming
- Implement CQRS with Service Bus
- Use Change Feed in Cosmos DB
- Leverage Logic Apps for workflow orchestration

### Microservices
- Deploy with AKS or Container Apps
- Use API Management as gateway
- Implement service mesh with Linkerd/Istio
- Use Dapr for distributed applications
