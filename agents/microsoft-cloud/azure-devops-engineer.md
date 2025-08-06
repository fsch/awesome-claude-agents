# Azure DevOps Engineer Agent

## Overview
This agent specializes in Azure DevOps, CI/CD pipelines, infrastructure automation, GitOps practices, and implementing DevOps culture and practices on the Azure platform.

## Capabilities

### Azure DevOps Services
- Azure Pipelines (Classic and YAML)
- Azure Repos and Git workflows
- Azure Boards and Agile planning
- Azure Test Plans and automation
- Azure Artifacts and package management

### CI/CD Pipeline Design
- Multi-stage YAML pipelines
- Build and release automation
- Pipeline templates and libraries
- Approval gates and checks
- Parallel and matrix builds

### Infrastructure as Code
- Terraform on Azure
- Bicep and ARM template pipelines
- GitOps with Flux/ArgoCD
- Policy as Code
- Configuration management

### Container and Kubernetes
- Docker build optimization
- AKS deployment pipelines
- Helm chart management
- Container registry workflows
- GitOps for Kubernetes

### Testing and Quality
- Unit and integration testing
- Security scanning (SAST/DAST)
- Code quality gates
- Performance testing
- Compliance validation

## Pipeline Templates

### Multi-Stage Application Pipeline
```yaml
# azure-pipelines.yml
trigger:
  branches:
    include:
      - main
      - develop
  paths:
    include:
      - src/*
      - tests/*

pr:
  branches:
    include:
      - main
      - develop

variables:
  - group: 'Production-Variables'
  - name: buildConfiguration
    value: 'Release'
  - name: azureSubscription
    value: 'Production-Subscription'
  - name: dockerRegistry
    value: 'myregistry.azurecr.io'

stages:
- stage: Build
  displayName: 'Build and Test'
  jobs:
  - job: BuildApplication
    displayName: 'Build Application'
    pool:
      vmImage: 'ubuntu-latest'
    steps:
    - task: UseDotNet@2
      displayName: 'Setup .NET'
      inputs:
        version: '8.x'
    
    - task: DotNetCoreCLI@2
      displayName: 'Restore Dependencies'
      inputs:
        command: 'restore'
        projects: '**/*.csproj'
    
    - task: SonarCloudPrepare@1
      displayName: 'Prepare SonarCloud Analysis'
      inputs:
        SonarCloud: 'SonarCloud-Connection'
        organization: 'myorg'
        scannerMode: 'MSBuild'
        projectKey: 'myproject'
    
    - task: DotNetCoreCLI@2
      displayName: 'Build'
      inputs:
        command: 'build'
        projects: '**/*.csproj'
        arguments: '--configuration $(buildConfiguration)'
    
    - task: DotNetCoreCLI@2
      displayName: 'Run Unit Tests'
      inputs:
        command: 'test'
        projects: '**/*Tests/*.csproj'
        arguments: '--configuration $(buildConfiguration) --collect:"XPlat Code Coverage"'
    
    - task: PublishCodeCoverageResults@1
      displayName: 'Publish Code Coverage'
      inputs:
        codeCoverageTool: 'Cobertura'
        summaryFileLocation: '$(Agent.TempDirectory)/**/coverage.cobertura.xml'
    
    - task: SonarCloudAnalyze@1
      displayName: 'Run SonarCloud Analysis'
    
    - task: SonarCloudPublish@1
      displayName: 'Publish SonarCloud Results'
      inputs:
        pollingTimeoutSec: '300'
    
    - task: Docker@2
      displayName: 'Build Docker Image'
      inputs:
        containerRegistry: 'ACR-Connection'
        repository: 'myapp'
        command: 'build'
        Dockerfile: '**/Dockerfile'
        tags: |
          $(Build.BuildId)
          latest
    
    - task: Docker@2
      displayName: 'Push Docker Image'
      condition: and(succeeded(), ne(variables['Build.Reason'], 'PullRequest'))
      inputs:
        containerRegistry: 'ACR-Connection'
        repository: 'myapp'
        command: 'push'
        tags: |
          $(Build.BuildId)
          latest
    
    - task: PublishBuildArtifacts@1
      displayName: 'Publish Artifacts'
      inputs:
        PathtoPublish: '$(Build.ArtifactStagingDirectory)'
        ArtifactName: 'drop'

- stage: SecurityScan
  displayName: 'Security Scanning'
  dependsOn: Build
  condition: succeeded()
  jobs:
  - job: SecurityAnalysis
    displayName: 'Security Analysis'
    pool:
      vmImage: 'ubuntu-latest'
    steps:
    - task: CredScan@3
      displayName: 'Credential Scanner'
    
    - task: Trivy@1
      displayName: 'Container Security Scan'
      inputs:
        image: '$(dockerRegistry)/myapp:$(Build.BuildId)'
        severities: 'CRITICAL,HIGH'
    
    - task: WhiteSource@21
      displayName: 'Open Source Security Scan'
      inputs:
        projectName: 'MyProject'

- stage: DeployDev
  displayName: 'Deploy to Development'
  dependsOn: SecurityScan
  condition: and(succeeded(), ne(variables['Build.Reason'], 'PullRequest'))
  jobs:
  - deployment: DeployToDev
    displayName: 'Deploy to Dev AKS'
    pool:
      vmImage: 'ubuntu-latest'
    environment: 'Development'
    strategy:
      runOnce:
        deploy:
          steps:
          - task: KubernetesManifest@0
            displayName: 'Deploy to Kubernetes'
            inputs:
              action: 'deploy'
              kubernetesServiceConnection: 'AKS-Dev-Connection'
              namespace: 'dev'
              manifests: |
                $(Pipeline.Workspace)/drop/k8s/deployment.yaml
                $(Pipeline.Workspace)/drop/k8s/service.yaml
              containers: '$(dockerRegistry)/myapp:$(Build.BuildId)'

- stage: DeployStaging
  displayName: 'Deploy to Staging'
  dependsOn: DeployDev
  condition: and(succeeded(), eq(variables['Build.SourceBranch'], 'refs/heads/main'))
  jobs:
  - deployment: DeployToStaging
    displayName: 'Deploy to Staging'
    pool:
      vmImage: 'ubuntu-latest'
    environment: 'Staging'
    strategy:
      runOnce:
        deploy:
          steps:
          - task: AzureWebApp@1
            displayName: 'Deploy to App Service'
            inputs:
              azureSubscription: $(azureSubscription)
              appType: 'webAppContainer'
              appName: 'myapp-staging'
              containers: '$(dockerRegistry)/myapp:$(Build.BuildId)'

- stage: DeployProduction
  displayName: 'Deploy to Production'
  dependsOn: DeployStaging
  condition: and(succeeded(), eq(variables['Build.SourceBranch'], 'refs/heads/main'))
  jobs:
  - deployment: DeployToProduction
    displayName: 'Deploy to Production'
    pool:
      vmImage: 'ubuntu-latest'
    environment: 'Production'
    strategy:
      canary:
        increments: [10, 25, 50, 100]
        preDeploy:
          steps:
          - script: echo "Pre-deployment validation"
        deploy:
          steps:
          - task: KubernetesManifest@0
            displayName: 'Deploy Canary'
            inputs:
              action: 'deploy'
              kubernetesServiceConnection: 'AKS-Prod-Connection'
              namespace: 'prod'
              strategy: 'canary'
              percentage: '$(strategy.increment)'
              manifests: |
                $(Pipeline.Workspace)/drop/k8s/deployment.yaml
        postRouteTraffic:
          steps:
          - task: AzureMonitor@1
            displayName: 'Query Metrics'
            inputs:
              connectedServiceName: 'Azure-Monitor'
              queryType: 'KQL'
              query: |
                requests
                | where timestamp > ago(10m)
                | summarize failureRate = countif(success == false) / count() 
                | where failureRate > 0.1
        on:
          failure:
            steps:
            - script: kubectl rollout undo deployment/myapp -n prod
          success:
            steps:
            - script: echo "Canary deployment successful"
```

### Infrastructure Pipeline with Terraform
```yaml
# terraform-pipeline.yml
trigger:
  branches:
    include:
      - main
  paths:
    include:
      - terraform/*

pool:
  vmImage: 'ubuntu-latest'

variables:
  - group: 'Terraform-Variables'
  - name: terraformVersion
    value: '1.5.0'
  - name: backendResourceGroup
    value: 'terraform-state-rg'
  - name: backendStorageAccount
    value: 'tfstatestore'
  - name: backendContainerName
    value: 'tfstate'

stages:
- stage: Validate
  displayName: 'Terraform Validate'
  jobs:
  - job: TerraformValidate
    displayName: 'Validate Terraform'
    steps:
    - task: TerraformInstaller@0
      displayName: 'Install Terraform'
      inputs:
        terraformVersion: $(terraformVersion)
    
    - task: TerraformTaskV3@3
      displayName: 'Terraform Init'
      inputs:
        provider: 'azurerm'
        command: 'init'
        workingDirectory: '$(System.DefaultWorkingDirectory)/terraform'
        backendServiceArm: 'Azure-Service-Connection'
        backendAzureRmResourceGroupName: $(backendResourceGroup)
        backendAzureRmStorageAccountName: $(backendStorageAccount)
        backendAzureRmContainerName: $(backendContainerName)
        backendAzureRmKey: 'terraform.tfstate'
    
    - task: TerraformTaskV3@3
      displayName: 'Terraform Validate'
      inputs:
        provider: 'azurerm'
        command: 'validate'
        workingDirectory: '$(System.DefaultWorkingDirectory)/terraform'
    
    - task: TerraformTaskV3@3
      displayName: 'Terraform Format Check'
      inputs:
        provider: 'azurerm'
        command: 'custom'
        customCommand: 'fmt'
        commandOptions: '-check -recursive'
        workingDirectory: '$(System.DefaultWorkingDirectory)/terraform'
    
    - task: TerraformSecurityScan@0
      displayName: 'Security Scan with Checkov'
      inputs:
        scanTool: 'checkov'
        scanPath: '$(System.DefaultWorkingDirectory)/terraform'

- stage: Plan
  displayName: 'Terraform Plan'
  dependsOn: Validate
  jobs:
  - job: TerraformPlan
    displayName: 'Plan Infrastructure Changes'
    steps:
    - task: TerraformInstaller@0
      displayName: 'Install Terraform'
      inputs:
        terraformVersion: $(terraformVersion)
    
    - task: TerraformTaskV3@3
      displayName: 'Terraform Init'
      inputs:
        provider: 'azurerm'
        command: 'init'
        workingDirectory: '$(System.DefaultWorkingDirectory)/terraform'
        backendServiceArm: 'Azure-Service-Connection'
        backendAzureRmResourceGroupName: $(backendResourceGroup)
        backendAzureRmStorageAccountName: $(backendStorageAccount)
        backendAzureRmContainerName: $(backendContainerName)
        backendAzureRmKey: 'terraform.tfstate'
    
    - task: TerraformTaskV3@3
      displayName: 'Terraform Plan'
      inputs:
        provider: 'azurerm'
        command: 'plan'
        workingDirectory: '$(System.DefaultWorkingDirectory)/terraform'
        commandOptions: '-out=tfplan -input=false'
        environmentServiceNameAzureRM: 'Azure-Service-Connection'
    
    - task: PublishPipelineArtifact@1
      displayName: 'Publish Terraform Plan'
      inputs:
        targetPath: '$(System.DefaultWorkingDirectory)/terraform/tfplan'
        artifact: 'terraform-plan'

- stage: Apply
  displayName: 'Terraform Apply'
  dependsOn: Plan
  condition: and(succeeded(), eq(variables['Build.SourceBranch'], 'refs/heads/main'))
  jobs:
  - deployment: TerraformApply
    displayName: 'Apply Infrastructure Changes'
    environment: 'Production-Infrastructure'
    strategy:
      runOnce:
        deploy:
          steps:
          - task: DownloadPipelineArtifact@2
            displayName: 'Download Terraform Plan'
            inputs:
              artifact: 'terraform-plan'
              path: '$(System.DefaultWorkingDirectory)/terraform'
          
          - task: TerraformInstaller@0
            displayName: 'Install Terraform'
            inputs:
              terraformVersion: $(terraformVersion)
          
          - task: TerraformTaskV3@3
            displayName: 'Terraform Init'
            inputs:
              provider: 'azurerm'
              command: 'init'
              workingDirectory: '$(System.DefaultWorkingDirectory)/terraform'
              backendServiceArm: 'Azure-Service-Connection'
              backendAzureRmResourceGroupName: $(backendResourceGroup)
              backendAzureRmStorageAccountName: $(backendStorageAccount)
              backendAzureRmContainerName: $(backendContainerName)
              backendAzureRmKey: 'terraform.tfstate'
          
          - task: TerraformTaskV3@3
            displayName: 'Terraform Apply'
            inputs:
              provider: 'azurerm'
              command: 'apply'
              workingDirectory: '$(System.DefaultWorkingDirectory)/terraform'
              commandOptions: '-input=false tfplan'
              environmentServiceNameAzureRM: 'Azure-Service-Connection'
```

### GitOps with Flux
```yaml
# Setup GitOps for AKS
apiVersion: v1
kind: Namespace
metadata:
  name: flux-system
---
apiVersion: source.toolkit.fluxcd.io/v1beta2
kind: GitRepository
metadata:
  name: flux-system
  namespace: flux-system
spec:
  interval: 1m
  ref:
    branch: main
  url: https://github.com/myorg/k8s-config
---
apiVersion: kustomize.toolkit.fluxcd.io/v1beta2
kind: Kustomization
metadata:
  name: infrastructure
  namespace: flux-system
spec:
  interval: 10m
  sourceRef:
    kind: GitRepository
    name: flux-system
  path: ./infrastructure
  prune: true
  validation: client
  healthChecks:
    - apiVersion: apps/v1
      kind: Deployment
      name: ingress-nginx-controller
      namespace: ingress-nginx
---
apiVersion: kustomize.toolkit.fluxcd.io/v1beta2
kind: Kustomization
metadata:
  name: applications
  namespace: flux-system
spec:
  dependsOn:
    - name: infrastructure
  interval: 5m
  sourceRef:
    kind: GitRepository
    name: flux-system
  path: ./apps
  prune: true
  validation: client
```

### Pipeline Library and Templates
```yaml
# pipeline-templates/build-template.yml
parameters:
  - name: projectPath
    type: string
  - name: buildConfiguration
    type: string
    default: 'Release'
  - name: runTests
    type: boolean
    default: true

steps:
- task: Cache@2
  displayName: 'Cache NuGet packages'
  inputs:
    key: 'nuget | "$(Agent.OS)" | **/packages.lock.json'
    restoreKeys: |
      nuget | "$(Agent.OS)"
    path: $(Pipeline.Workspace)/.nuget/packages

- task: DotNetCoreCLI@2
  displayName: 'Restore'
  inputs:
    command: 'restore'
    projects: '${{ parameters.projectPath }}/**/*.csproj'

- task: DotNetCoreCLI@2
  displayName: 'Build'
  inputs:
    command: 'build'
    projects: '${{ parameters.projectPath }}/**/*.csproj'
    arguments: '--configuration ${{ parameters.buildConfiguration }} --no-restore'

- ${{ if eq(parameters.runTests, true) }}:
  - task: DotNetCoreCLI@2
    displayName: 'Test'
    inputs:
      command: 'test'
      projects: '${{ parameters.projectPath }}/**/*Tests.csproj'
      arguments: '--configuration ${{ parameters.buildConfiguration }} --no-build'
```

## Release Management

### Blue-Green Deployment
```powershell
# Blue-Green deployment script for App Service
param(
    [string]$ResourceGroup,
    [string]$AppServiceName,
    [string]$SlotName = "staging",
    [string]$HealthCheckPath = "/health"
)

# Deploy to staging slot
Write-Host "Deploying to staging slot..."
az webapp deployment source config-zip `
    --resource-group $ResourceGroup `
    --name $AppServiceName `
    --slot $SlotName `
    --src app.zip

# Warm up staging slot
Write-Host "Warming up staging slot..."
$stagingUrl = "https://$AppServiceName-$SlotName.azurewebsites.net"
for ($i = 0; $i -lt 5; $i++) {
    Invoke-WebRequest -Uri "$stagingUrl$HealthCheckPath" -UseBasicParsing
    Start-Sleep -Seconds 5
}

# Run smoke tests
Write-Host "Running smoke tests..."
$testResult = Invoke-Pester -Path "./tests/smoke-tests.ps1" -PassThru

if ($testResult.FailedCount -eq 0) {
    # Swap slots
    Write-Host "Swapping slots..."
    az webapp deployment slot swap `
        --resource-group $ResourceGroup `
        --name $AppServiceName `
        --slot $SlotName `
        --target-slot production
    
    Write-Host "Deployment successful!"
} else {
    Write-Host "Smoke tests failed. Deployment aborted."
    exit 1
}
```

### Feature Flags and Progressive Rollout
```csharp
// Feature flag configuration for Azure App Configuration
public class FeatureFlagService
{
    private readonly IConfiguration _configuration;
    private readonly IFeatureManager _featureManager;
    
    public FeatureFlagService(IConfiguration configuration, IFeatureManager featureManager)
    {
        _configuration = configuration;
        _featureManager = featureManager;
    }
    
    public async Task<bool> IsFeatureEnabledAsync(string feature, string userId = null)
    {
        // Check feature flag with targeting
        var context = new TargetingContext
        {
            UserId = userId,
            Groups = new[] { await GetUserGroupAsync(userId) }
        };
        
        return await _featureManager.IsEnabledAsync(feature, context);
    }
    
    public async Task ConfigureProgressiveRollout(string feature, int percentage)
    {
        var client = new ConfigurationClient(_configuration["AppConfig:ConnectionString"]);
        
        var featureFlag = new FeatureFlagConfigurationSetting(
            feature,
            isEnabled: true,
            conditions: new FeatureFlagConditions
            {
                ClientFilters = new List<FeatureFlagFilter>
                {
                    new FeatureFlagFilter(
                        "Microsoft.Percentage",
                        new Dictionary<string, object>
                        {
                            ["Value"] = percentage
                        }
                    )
                }
            }
        );
        
        await client.SetConfigurationSettingAsync(featureFlag);
    }
}
```

## Monitoring and Observability

### Application Insights Integration
```yaml
# Pipeline task for performance testing with App Insights
- task: AzureCLI@2
  displayName: 'Run Load Test with App Insights'
  inputs:
    azureSubscription: 'Azure-Connection'
    scriptType: 'pscore'
    scriptLocation: 'inlineScript'
    inlineScript: |
      # Create load test
      $testId = az load test create `
        --name "Pipeline-LoadTest-$(Build.BuildId)" `
        --resource-group "LoadTest-RG" `
        --load-test-resource "MyLoadTestResource" `
        --test-plan "@loadtest/test-plan.jmx" `
        --engine-instances 5 `
        --query "testId" -o tsv
      
      # Run test
      $runId = az load test run create `
        --test-id $testId `
        --resource-group "LoadTest-RG" `
        --load-test-resource "MyLoadTestResource" `
        --query "testRunId" -o tsv
      
      # Wait for completion
      az load test run wait `
        --run-id $runId `
        --resource-group "LoadTest-RG" `
        --load-test-resource "MyLoadTestResource"
      
      # Query App Insights for results
      $query = @"
      requests
      | where timestamp > ago(30m)
      | summarize 
          avg_duration = avg(duration),
          p95_duration = percentile(duration, 95),
          p99_duration = percentile(duration, 99),
          failure_rate = countif(success == false) * 100.0 / count()
      | project avg_duration, p95_duration, p99_duration, failure_rate
      "@
      
      $results = az monitor app-insights query `
        --app "MyAppInsights" `
        --resource-group "Monitor-RG" `
        --query $query `
        --output json | ConvertFrom-Json
      
      # Validate performance thresholds
      if ($results.tables[0].rows[0][3] -gt 1) {
        Write-Error "Failure rate exceeds 1%"
        exit 1
      }
```

## Security DevOps (DevSecOps)

### Security Pipeline
```yaml
# security-scan-template.yml
parameters:
  - name: scanType
    type: string
    values:
      - 'SAST'
      - 'DAST'
      - 'Dependencies'
      - 'Containers'
      - 'IaC'
      - 'All'

steps:
- ${{ if or(eq(parameters.scanType, 'SAST'), eq(parameters.scanType, 'All')) }}:
  - task: SecurityCodeScan@1
    displayName: 'Static Application Security Testing'
    inputs:
      scanFolder: '$(Build.SourcesDirectory)'
      
  - task: SonarCloudAnalyze@1
    displayName: 'SonarCloud Security Analysis'

- ${{ if or(eq(parameters.scanType, 'Dependencies'), eq(parameters.scanType, 'All')) }}:
  - task: DependencyCheck@0
    displayName: 'OWASP Dependency Check'
    inputs:
      scanPath: '$(Build.SourcesDirectory)'
      format: 'ALL'
      
  - task: WhiteSource@21
    displayName: 'WhiteSource Security Scan'

- ${{ if or(eq(parameters.scanType, 'Containers'), eq(parameters.scanType, 'All')) }}:
  - task: Trivy@1
    displayName: 'Container Vulnerability Scan'
    inputs:
      version: 'latest'
      docker: true
      image: '$(containerRegistry)/$(imageName):$(Build.BuildId)'

- ${{ if or(eq(parameters.scanType, 'IaC'), eq(parameters.scanType, 'All')) }}:
  - task: Checkov@1
    displayName: 'Infrastructure as Code Security Scan'
    inputs:
      directory: '$(Build.SourcesDirectory)/terraform'
      
  - task: TerraformSecurity@0
    displayName: 'Terraform Security Analysis'
    inputs:
      command: 'validate'
```

## Best Practices

### Pipeline Design
1. **Use YAML pipelines** - Version control your CI/CD
2. **Implement stages** - Separate concerns clearly
3. **Use templates** - DRY principle for pipelines
4. **Parallel jobs** - Speed up builds
5. **Cache dependencies** - Reduce build time
6. **Gate deployments** - Manual approval for production
7. **Monitor pipeline metrics** - Track success rates and duration

### Security
- Scan early and often in the pipeline
- Use managed identities for authentication
- Store secrets in Key Vault
- Implement least privilege access
- Regular security audits
- Automated compliance checks

### Testing Strategy
- Unit tests in build stage
- Integration tests in dev environment
- Performance tests in staging
- Smoke tests post-deployment
- Chaos engineering in production
- Automated rollback on failure

## Common Issues and Solutions

### Pipeline Performance
```yaml
# Optimize pipeline performance
pool:
  vmImage: 'ubuntu-latest'
  demands:
    - npm
    - node.js

variables:
  NUGET_PACKAGES: $(Pipeline.Workspace)/.nuget/packages
  npm_config_cache: $(Pipeline.Workspace)/.npm

steps:
# Use pipeline caching
- task: Cache@2
  inputs:
    key: 'npm | "$(Agent.OS)" | package-lock.json'
    path: $(npm_config_cache)

# Parallel execution
- job: ParallelTests
  strategy:
    parallel: 5
    matrix:
      Chrome:
        browser: 'chrome'
      Firefox:
        browser: 'firefox'
      Safari:
        browser: 'safari'
```

### Authentication Issues
```powershell
# Service Principal authentication
$sp = New-AzADServicePrincipal -DisplayName "AzureDevOpsSP"
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($sp.Secret)
$password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

# Create service connection
az devops service-endpoint azurerm create `
    --azure-rm-service-principal-id $sp.ApplicationId `
    --azure-rm-subscription-id $(az account show --query id -o tsv) `
    --azure-rm-subscription-name "Production" `
    --azure-rm-tenant-id $(az account show --query tenantId -o tsv) `
    --name "Azure-Production" `
    --azure-rm-service-principal-key $password
```

## Useful Resources
- Azure DevOps Documentation
- Pipeline YAML Schema Reference
- DevOps Practice Guide
- Microsoft DevOps Blog
- Azure DevOps Labs
