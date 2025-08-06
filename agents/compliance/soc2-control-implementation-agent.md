# SOC2 Control Implementation Agent

## Overview
This agent specializes in implementing specific SOC2 controls across all Trust Service Criteria, providing technical implementation guidance, configuration templates, and validation procedures.

## Capabilities

### Control Implementation
- Technical control deployment
- Administrative control procedures
- Control configuration templates
- Implementation validation
- Control effectiveness testing
- Remediation guidance

### Technology Stack Coverage
- Cloud platforms (AWS, Azure, GCP)
- Identity providers (Okta, Auth0, Azure AD)
- Security tools (SIEM, EDR, DLP)
- Development tools (Git, CI/CD)
- Infrastructure as Code
- Monitoring and logging

## Control Implementation Templates

### CC6.1 - Logical Access Controls
```python
# Multi-factor Authentication Implementation
class MFAImplementation:
    def __init__(self, identity_provider):
        self.idp = identity_provider
        self.enforcement_policy = {
            'require_mfa': True,
            'allowed_methods': ['authenticator_app', 'hardware_token', 'sms'],
            'grace_period_days': 7,
            'remember_device_days': 30,
            'exempt_networks': [],  # No exemptions for SOC2
            'high_risk_apps': ['admin_console', 'financial_systems', 'hr_systems']
        }
    
    def implement_okta_mfa(self):
        """Implement MFA in Okta"""
        from okta.client import Client as OktaClient
        
        okta = OktaClient({
            'orgUrl': 'https://your-org.okta.com',
            'token': os.environ['OKTA_API_TOKEN']
        })
        
        # Create MFA policy
        mfa_policy = {
            'name': 'SOC2 MFA Policy',
            'status': 'ACTIVE',
            'description': 'Enforces MFA for all users per SOC2 requirements',
            'priority': 1,
            'conditions': {
                'people': {
                    'users': {
                        'exclude': []  # No exclusions
                    },
                    'groups': {
                        'include': ['EVERYONE']
                    }
                }
            },
            'rules': [{
                'name': 'Require MFA',
                'priority': 1,
                'status': 'ACTIVE',
                'conditions': {
                    'network': {
                        'connection': 'ANYWHERE'
                    },
                    'authContext': {
                        'authType': 'ANY'
                    }
                },
                'actions': {
                    'signon': {
                        'access': 'CHALLENGE',
                        'requireFactor': True,
                        'factorPromptMode': 'ALWAYS',
                        'factorLifetime': 0
                    }
                }
            }]
        }
        
        # Create policy
        created_policy = okta.create_policy(mfa_policy)
        
        # Configure factor enrollment
        enrollment_policy = {
            'name': 'SOC2 Factor Enrollment',
            'status': 'ACTIVE',
            'description': 'Factor enrollment requirements',
            'settings': {
                'factors': {
                    'okta_authenticator': {
                        'enroll': 'REQUIRED',
                        'consent': 'NONE'
                    },
                    'okta_sms': {
                        'enroll': 'OPTIONAL',
                        'consent': 'NONE'
                    },
                    'okta_email': {
                        'enroll': 'NOT_ALLOWED'  # Email not sufficient for SOC2
                    }
                }
            }
        }
        
        return {
            'policy_id': created_policy.id,
            'implementation_date': datetime.now(),
            'validation_steps': self.get_validation_steps()
        }
    
    def implement_azure_ad_mfa(self):
        """Implement MFA in Azure AD"""
        from azure.identity import ClientSecretCredential
        from msgraph import GraphServiceClient
        
        credential = ClientSecretCredential(
            tenant_id=os.environ['AZURE_TENANT_ID'],
            client_id=os.environ['AZURE_CLIENT_ID'],
            client_secret=os.environ['AZURE_CLIENT_SECRET']
        )
        
        client = GraphServiceClient(
            credentials=credential,
            scopes=['https://graph.microsoft.com/.default']
        )
        
        # Create Conditional Access Policy
        ca_policy = {
            'displayName': 'SOC2 MFA Policy',
            'state': 'enabled',
            'conditions': {
                'users': {
                    'includeUsers': ['All']
                },
                'applications': {
                    'includeApplications': ['All']
                },
                'locations': {
                    'includeLocations': ['All']
                }
            },
            'grantControls': {
                'operator': 'OR',
                'builtInControls': ['mfa'],
                'customAuthenticationFactors': [],
                'termsOfUse': []
            }
        }
        
        # Create policy
        created_policy = client.policies.conditional_access_policies.post(ca_policy)
        
        # Configure authentication methods
        auth_methods_policy = {
            'authenticationMethodConfigurations': [
                {
                    'id': 'MicrosoftAuthenticator',
                    'state': 'enabled',
                    'includeTarget': {
                        'targetType': 'group',
                        'id': 'all_users'
                    }
                },
                {
                    'id': 'Fido2',
                    'state': 'enabled',
                    'includeTarget': {
                        'targetType': 'group',
                        'id': 'all_users'
                    }
                }
            ]
        }
        
        client.policies.authentication_methods_policy.patch(auth_methods_policy)
        
        return {
            'policy_id': created_policy.id,
            'implementation_date': datetime.now(),
            'validation_steps': self.get_validation_steps()
        }
    
    def get_validation_steps(self):
        """Return validation steps for MFA implementation"""
        return [
            {
                'step': 1,
                'description': 'Verify all users have MFA enrolled',
                'query': 'SELECT user_id, mfa_enrolled FROM users WHERE mfa_enrolled = false',
                'expected_result': 'Empty result set'
            },
            {
                'step': 2,
                'description': 'Test MFA challenge on login',
                'procedure': 'Attempt login with test account and verify MFA prompt',
                'expected_result': 'MFA challenge presented'
            },
            {
                'step': 3,
                'description': 'Verify MFA methods meet requirements',
                'query': 'SELECT user_id, mfa_methods FROM user_mfa WHERE method IN ("sms", "email")',
                'expected_result': 'No users with only SMS or email MFA'
            }
        ]

# Role-Based Access Control Implementation
class RBACImplementation:
    def __init__(self):
        self.roles = {
            'admin': {
                'permissions': ['full_access'],
                'mfa_required': True,
                'session_timeout': 900,  # 15 minutes
                'ip_restrictions': True
            },
            'developer': {
                'permissions': ['code_read', 'code_write', 'deploy_staging'],
                'mfa_required': True,
                'session_timeout': 3600  # 1 hour
            },
            'analyst': {
                'permissions': ['data_read', 'report_create'],
                'mfa_required': True,
                'session_timeout': 7200  # 2 hours
            },
            'viewer': {
                'permissions': ['read_only'],
                'mfa_required': True,
                'session_timeout': 14400  # 4 hours
            }
        }
    
    def implement_aws_rbac(self):
        """Implement RBAC in AWS"""
        import boto3
        
        iam = boto3.client('iam')
        
        # Create roles based on least privilege
        for role_name, config in self.roles.items():
            # Create role
            trust_policy = {
                'Version': '2012-10-17',
                'Statement': [{
                    'Effect': 'Allow',
                    'Principal': {
                        'AWS': f'arn:aws:iam::{AWS_ACCOUNT_ID}:root'
                    },
                    'Action': 'sts:AssumeRole',
                    'Condition': {
                        'Bool': {
                            'aws:MultiFactorAuthPresent': 'true'
                        },
                        'NumericLessThan': {
                            'aws:MultiFactorAuthAge': str(config['session_timeout'])
                        }
                    }
                }]
            }
            
            iam.create_role(
                RoleName=f'SOC2-{role_name}',
                AssumeRolePolicyDocument=json.dumps(trust_policy),
                Description=f'SOC2 compliant role for {role_name}',
                MaxSessionDuration=config['session_timeout']
            )
            
            # Attach permissions
            self._create_and_attach_policy(iam, role_name, config['permissions'])
        
        # Create boundary policy to prevent privilege escalation
        boundary_policy = {
            'Version': '2012-10-17',
            'Statement': [{
                'Effect': 'Deny',
                'Action': [
                    'iam:CreateAccessKey',
                    'iam:DeleteRole',
                    'iam:DeleteRolePolicy',
                    'iam:PutRolePolicy',
                    'iam:AttachRolePolicy',
                    'iam:DetachRolePolicy'
                ],
                'Resource': '*'
            }]
        }
        
        iam.create_policy(
            PolicyName='SOC2-PermissionsBoundary',
            PolicyDocument=json.dumps(boundary_policy),
            Description='Prevents privilege escalation'
        )
    
    def implement_database_rbac(self):
        """Implement database-level RBAC"""
        # PostgreSQL implementation
        sql_commands = []
        
        for role_name, config in self.roles.items():
            sql_commands.extend([
                f"CREATE ROLE soc2_{role_name} WITH LOGIN ENCRYPTED PASSWORD '{{vault:database/creds/{role_name}}}';",
                f"ALTER ROLE soc2_{role_name} SET statement_timeout = {config['session_timeout'] * 1000};",
                f"ALTER ROLE soc2_{role_name} SET idle_in_transaction_session_timeout = 300000;"  # 5 minutes
            ])
            
            # Grant appropriate permissions
            if 'full_access' in config['permissions']:
                sql_commands.append(f"GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO soc2_{role_name};")
            elif 'data_read' in config['permissions']:
                sql_commands.append(f"GRANT SELECT ON ALL TABLES IN SCHEMA public TO soc2_{role_name};")
            elif 'read_only' in config['permissions']:
                sql_commands.append(f"GRANT SELECT ON ALL TABLES IN SCHEMA reporting TO soc2_{role_name};")
        
        # Enable row-level security
        sql_commands.extend([
            "ALTER TABLE sensitive_data ENABLE ROW LEVEL SECURITY;",
            "CREATE POLICY sensitive_data_policy ON sensitive_data FOR ALL TO PUBLIC USING (user_id = current_user);"
        ])
        
        return sql_commands
```

### CC7.2 - System Monitoring
```javascript
// Comprehensive monitoring implementation
class SystemMonitoringImplementation {
    constructor() {
        this.monitoringStack = {
            metrics: 'Prometheus/Grafana',
            logs: 'ELK Stack',
            security: 'Wazuh/OSSEC',
            apm: 'New Relic/Datadog',
            uptime: 'Pingdom/UptimeRobot'
        };
    }
    
    implementPrometheusMonitoring() {
        // Prometheus configuration for SOC2
        const prometheusConfig = `
global:
  scrape_interval: 15s
  evaluation_interval: 15s
  external_labels:
    environment: 'production'
    compliance: 'soc2'

alerting:
  alertmanagers:
    - static_configs:
      - targets: ['alertmanager:9093']

rule_files:
  - '/etc/prometheus/rules/soc2_alerts.yml'

scrape_configs:
  - job_name: 'node_exporter'
    static_configs:
      - targets: ['node-exporter:9100']
    
  - job_name: 'application'
    static_configs:
      - targets: ['app:8080']
    metrics_path: '/metrics'
    
  - job_name: 'database'
    static_configs:
      - targets: ['postgres-exporter:9187']
    
  - job_name: 'blackbox'
    metrics_path: /probe
    params:
      module: [http_2xx]
    static_configs:
      - targets:
        - https://app.company.com
        - https://api.company.com
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: blackbox-exporter:9115
`;

        // Alert rules for SOC2 compliance
        const alertRules = `
groups:
  - name: soc2_availability
    interval: 30s
    rules:
      - alert: ServiceDown
        expr: up == 0
        for: 5m
        labels:
          severity: critical
          compliance: soc2
        annotations:
          summary: "Service {{ $labels.job }} is down"
          description: "{{ $labels.instance }} has been down for more than 5 minutes"
          
      - alert: HighResponseTime
        expr: http_request_duration_seconds{quantile="0.99"} > 2
        for: 10m
        labels:
          severity: warning
          compliance: soc2
        annotations:
          summary: "High response time detected"
          description: "99th percentile response time is above 2 seconds"
          
      - alert: DiskSpaceLow
        expr: (node_filesystem_avail_bytes / node_filesystem_size_bytes) < 0.15
        for: 5m
        labels:
          severity: warning
          compliance: soc2
        annotations:
          summary: "Low disk space"
          description: "Less than 15% disk space available on {{ $labels.instance }}"
          
  - name: soc2_security
    interval: 30s
    rules:
      - alert: UnauthorizedAccessAttempt
        expr: rate(authentication_failures_total[5m]) > 10
        for: 5m
        labels:
          severity: high
          compliance: soc2
          security: true
        annotations:
          summary: "Multiple failed authentication attempts"
          description: "More than 10 failed auth attempts in 5 minutes"
          
      - alert: PrivilegedAccountUsage
        expr: privileged_operation_total > 0
        for: 1m
        labels:
          severity: info
          compliance: soc2
          audit: required
        annotations:
          summary: "Privileged operation detected"
          description: "Privileged operation performed by {{ $labels.user }}"
`;

        return {
            prometheusConfig,
            alertRules,
            dashboards: this.createGrafanaDashboards()
        };
    }
    
    implementELKStack() {
        // Elasticsearch configuration
        const elasticsearchConfig = {
            cluster: {
                name: 'soc2-logging-cluster',
                routing: {
                    allocation: {
                        awareness: {
                            attributes: 'zone'
                        }
                    }
                }
            },
            node: {
                attr: {
                    zone: '${ZONE}'
                }
            },
            network: {
                host: '0.0.0.0'
            },
            xpack: {
                security: {
                    enabled: true,
                    transport: {
                        ssl: {
                            enabled: true,
                            verification_mode: 'certificate'
                        }
                    },
                    http: {
                        ssl: {
                            enabled: true
                        }
                    }
                }
            },
            indices: {
                lifecycle: {
                    poll_interval: '10m'
                }
            }
        };
        
        // Logstash pipeline for SOC2
        const logstashPipeline = `
input {
  beats {
    port => 5044
    ssl => true
    ssl_certificate_authorities => ["/etc/logstash/ca.crt"]
    ssl_certificate => "/etc/logstash/server.crt"
    ssl_key => "/etc/logstash/server.key"
  }
}

filter {
  # Parse application logs
  if [fields][log_type] == "application" {
    grok {
      match => {
        "message" => "%{TIMESTAMP_ISO8601:timestamp} %{LOGLEVEL:level} \\[%{DATA:thread}\\] %{DATA:logger} - %{GREEDYDATA:message}"
      }
    }
    
    # Extract user and session info for audit
    if [message] =~ /user_id=/ {
      grok {
        match => {
          "message" => "user_id=%{DATA:user_id}"
        }
      }
    }
  }
  
  # Parse security logs
  if [fields][log_type] == "security" {
    grok {
      match => {
        "message" => "%{TIMESTAMP_ISO8601:timestamp} %{DATA:event_type} user=%{DATA:user} ip=%{IP:source_ip} result=%{DATA:result}"
      }
    }
    
    # Add GeoIP data
    geoip {
      source => "source_ip"
      target => "geoip"
    }
    
    # Flag suspicious activity
    if [event_type] == "authentication" and [result] == "failure" {
      mutate {
        add_tag => ["security_alert", "failed_auth"]
      }
    }
  }
  
  # Add SOC2 compliance fields
  mutate {
    add_field => {
      "compliance_framework" => "SOC2"
      "retention_days" => 365
      "data_classification" => "internal"
    }
  }
  
  # Hash sensitive data
  if [user_id] {
    fingerprint {
      source => "user_id"
      target => "user_id_hash"
      method => "SHA256"
      key => "${HASH_KEY}"
    }
    mutate {
      remove_field => ["user_id"]
    }
  }
}

output {
  elasticsearch {
    hosts => ["https://elasticsearch:9200"]
    ssl => true
    ssl_certificate_verification => true
    cacert => "/etc/logstash/ca.crt"
    user => "${ELASTIC_USER}"
    password => "${ELASTIC_PASSWORD}"
    index => "soc2-logs-%{+YYYY.MM.dd}"
    template_name => "soc2-logs"
    template => "/etc/logstash/templates/soc2-logs.json"
  }
  
  # Send security alerts to SIEM
  if "security_alert" in [tags] {
    http {
      url => "${SIEM_WEBHOOK_URL}"
      http_method => "post"
      format => "json"
      mapping => {
        "alert_type" => "%{event_type}"
        "user" => "%{user}"
        "source_ip" => "%{source_ip}"
        "timestamp" => "%{timestamp}"
        "severity" => "high"
      }
    }
  }
}
`;

        // Kibana saved searches and visualizations
        const kibanaDashboards = [
            {
                title: 'SOC2 Security Overview',
                visualizations: [
                    'Failed Authentication Attempts',
                    'Privileged Access Usage',
                    'Security Events by Type',
                    'Geographic Access Map',
                    'User Activity Timeline'
                ]
            },
            {
                title: 'SOC2 Availability Metrics',
                visualizations: [
                    'Service Uptime',
                    'Response Time Trends',
                    'Error Rate by Service',
                    'Resource Utilization',
                    'SLA Compliance'
                ]
            },
            {
                title: 'SOC2 Audit Trail',
                searches: [
                    'Administrative Actions',
                    'Data Access Logs',
                    'Configuration Changes',
                    'User Provisioning Events',
                    'Security Policy Violations'
                ]
            }
        ];
        
        return {
            elasticsearchConfig,
            logstashPipeline,
            kibanaDashboards
        };
    }
    
    createGrafanaDashboards() {
        return {
            availability: {
                title: 'SOC2 Availability Dashboard',
                panels: [
                    {
                        title: 'Service Uptime',
                        type: 'stat',
                        targets: [{
                            expr: 'avg_over_time(up[30d]) * 100'
                        }]
                    },
                    {
                        title: 'Response Time',
                        type: 'graph',
                        targets: [{
                            expr: 'histogram_quantile(0.99, rate(http_request_duration_seconds_bucket[5m]))'
                        }]
                    },
                    {
                        title: 'Error Rate',
                        type: 'graph',
                        targets: [{
                            expr: 'rate(http_requests_total{status=~"5.."}[5m])'
                        }]
                    }
                ]
            },
            security: {
                title: 'SOC2 Security Dashboard',
                panels: [
                    {
                        title: 'Authentication Failures',
                        type: 'graph',
                        targets: [{
                            expr: 'rate(authentication_failures_total[5m])'
                        }]
                    },
                    {
                        title: 'Privileged Operations',
                        type: 'table',
                        targets: [{
                            expr: 'privileged_operation_total'
                        }]
                    }
                ]
            }
        };
    }
}
```

### CC8.1 - Change Management
```python
# Change management control implementation
class ChangeManagementImplementation:
    def __init__(self):
        self.change_types = {
            'standard': {
                'approval_required': False,
                'testing_required': True,
                'documentation_required': True,
                'rollback_plan_required': True
            },
            'normal': {
                'approval_required': True,
                'approval_levels': 1,
                'testing_required': True,
                'documentation_required': True,
                'rollback_plan_required': True
            },
            'emergency': {
                'approval_required': True,
                'approval_levels': 2,
                'testing_required': False,  # Post-implementation
                'documentation_required': True,
                'rollback_plan_required': True
            }
        }
    
    def implement_gitlab_change_control(self):
        """Implement change control in GitLab"""
        # .gitlab-ci.yml for SOC2 compliant deployments
        gitlab_ci = """
stages:
  - validate
  - test
  - security-scan
  - approval
  - deploy
  - verify

variables:
  CHANGE_TICKET: ${CI_COMMIT_MESSAGE}
  APPROVERS_REQUIRED: 2

# Validate change ticket exists
validate:change-ticket:
  stage: validate
  script:
    - |
      if [[ ! "$CI_COMMIT_MESSAGE" =~ ^(CHANGE-[0-9]+|EMERGENCY-[0-9]+) ]]; then
        echo "Error: Commit message must start with CHANGE-XXXX or EMERGENCY-XXXX"
        exit 1
      fi
    - |
      # Validate change ticket in ITSM
      TICKET_STATUS=$(curl -s https://itsm.company.com/api/tickets/${CHANGE_TICKET} | jq -r '.status')
      if [[ "$TICKET_STATUS" != "Approved" ]]; then
        echo "Error: Change ticket ${CHANGE_TICKET} is not approved"
        exit 1
      fi
  only:
    - master
    - main

# Run comprehensive tests
test:unit:
  stage: test
  script:
    - npm install
    - npm run test:unit
    - npm run test:integration
  coverage: '/Coverage: ([0-9.]+)%/'
  artifacts:
    reports:
      coverage_report:
        coverage_format: cobertura
        path: coverage/cobertura-coverage.xml

# Security scanning
security:sast:
  stage: security-scan
  script:
    - npm audit --production
    - trivy fs --exit-code 1 --severity HIGH,CRITICAL .
    - semgrep --config=auto --error

security:dependency-check:
  stage: security-scan
  script:
    - safety check --json
    - snyk test --severity-threshold=high

# Manual approval gate
approval:production:
  stage: approval
  script:
    - echo "Waiting for manual approval..."
  when: manual
  only:
    - master
    - main
  allow_failure: false

# Deploy with audit trail
deploy:production:
  stage: deploy
  script:
    - |
      # Log deployment start
      curl -X POST https://audit-api.company.com/deployments \
        -H "Content-Type: application/json" \
        -d '{
          "environment": "production",
          "version": "'$CI_COMMIT_SHA'",
          "deployer": "'$GITLAB_USER_LOGIN'",
          "change_ticket": "'$CHANGE_TICKET'",
          "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"
        }'
    
    - |
      # Deploy application
      kubectl set image deployment/app app=$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
      kubectl rollout status deployment/app
    
    - |
      # Verify deployment
      ./scripts/smoke-tests.sh
      
  environment:
    name: production
    url: https://app.company.com
  only:
    - master
    - main

# Post-deployment verification
verify:monitoring:
  stage: verify
  script:
    - |
      # Check error rates
      ERROR_RATE=$(curl -s https://metrics.company.com/api/error-rate | jq -r '.rate')
      if (( $(echo "$ERROR_RATE > 0.01" | bc -l) )); then
        echo "Error rate above threshold: $ERROR_RATE"
        kubectl rollout undo deployment/app
        exit 1
      fi
    
    - |
      # Update change ticket
      curl -X PATCH https://itsm.company.com/api/tickets/${CHANGE_TICKET} \
        -H "Content-Type: application/json" \
        -d '{"status": "Implemented", "implementation_date": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"}'
  only:
    - master
    - main

# Rollback job
rollback:production:
  stage: deploy
  script:
    - kubectl rollout undo deployment/app
    - |
      curl -X POST https://audit-api.company.com/rollbacks \
        -H "Content-Type: application/json" \
        -d '{
          "environment": "production",
          "reason": "'$ROLLBACK_REASON'",
          "initiated_by": "'$GITLAB_USER_LOGIN'",
          "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"
        }'
  when: manual
  only:
    - master
    - main
"""
        
        # Merge request template
        merge_request_template = """
## Change Description
<!-- Provide a clear description of the change -->

## Change Ticket
- Ticket Number: CHANGE-XXXX
- Change Type: [ ] Standard [ ] Normal [ ] Emergency

## Testing Evidence
- [ ] Unit tests passing
- [ ] Integration tests passing
- [ ] Performance tests completed
- [ ] Security scan clean

## Deployment Checklist
- [ ] Code reviewed by at least 2 developers
- [ ] Documentation updated
- [ ] Rollback plan documented
- [ ] Monitoring alerts configured
- [ ] Stakeholders notified

## Rollback Plan
<!-- Describe how to rollback this change if needed -->

## Risk Assessment
- Risk Level: [ ] Low [ ] Medium [ ] High
- Impact: [ ] Low [ ] Medium [ ] High

## Approvals Required
- [ ] Development Lead
- [ ] Security Team (if security changes)
- [ ] Operations Team
- [ ] Product Owner
"""
        
        return {
            'gitlab_ci': gitlab_ci,
            'merge_request_template': merge_request_template,
            'branch_protection_rules': {
                'master': {
                    'push_rules': {
                        'member_check': True,
                        'prevent_secrets': True,
                        'commit_message_regex': '^(CHANGE|EMERGENCY)-[0-9]+',
                        'branch_name_regex': '^(feature|bugfix|hotfix)/.+$'
                    },
                    'merge_request_approvals': {
                        'approvals_before_merge': 2,
                        'reset_approvals_on_push': True,
                        'disable_overriding_approvers': True
                    }
                }
            }
        }
    
    def implement_database_change_control(self):
        """Database change control using Flyway/Liquibase"""
        # Liquibase change control
        liquibase_config = """
<?xml version="1.0" encoding="UTF-8"?>
<databaseChangeLog
    xmlns="http://www.liquibase.org/xml/ns/dbchangelog"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xsi:schemaLocation="http://www.liquibase.org/xml/ns/dbchangelog
        http://www.liquibase.org/xml/ns/dbchangelog/dbchangelog-4.0.xsd">

    <!-- Change set template with SOC2 requirements -->
    <changeSet id="CHANGE-1234" author="developer@company.com">
        <comment>Add audit columns to user table for SOC2 compliance</comment>
        
        <!-- Pre-conditions -->
        <preConditions onFail="MARK_RAN">
            <tableExists tableName="users"/>
            <not>
                <columnExists tableName="users" columnName="created_at"/>
            </not>
        </preConditions>
        
        <!-- Changes -->
        <addColumn tableName="users">
            <column name="created_at" type="timestamp" defaultValueComputed="CURRENT_TIMESTAMP">
                <constraints nullable="false"/>
            </column>
            <column name="created_by" type="varchar(255)">
                <constraints nullable="false"/>
            </column>
            <column name="updated_at" type="timestamp" defaultValueComputed="CURRENT_TIMESTAMP">
                <constraints nullable="false"/>
            </column>
            <column name="updated_by" type="varchar(255)">
                <constraints nullable="false"/>
            </column>
        </addColumn>
        
        <!-- Create audit trigger -->
        <sql>
            CREATE OR REPLACE FUNCTION update_updated_at_column()
            RETURNS TRIGGER AS $$
            BEGIN
                NEW.updated_at = CURRENT_TIMESTAMP;
                RETURN NEW;
            END;
            $$ language 'plpgsql';
            
            CREATE TRIGGER update_users_updated_at BEFORE UPDATE
            ON users FOR EACH ROW EXECUTE PROCEDURE update_updated_at_column();
        </sql>
        
        <!-- Rollback -->
        <rollback>
            <dropColumn tableName="users" columnName="created_at"/>
            <dropColumn tableName="users" columnName="created_by"/>
            <dropColumn tableName="users" columnName="updated_at"/>
            <dropColumn tableName="users" columnName="updated_by"/>
            <sql>
                DROP TRIGGER IF EXISTS update_users_updated_at ON users;
                DROP FUNCTION IF EXISTS update_updated_at_column();
            </sql>
        </rollback>
    </changeSet>

    <!-- Stored procedure for change auditing -->
    <changeSet id="CHANGE-1235" author="dba@company.com">
        <comment>Create stored procedure for database change auditing</comment>
        <createProcedure>
            CREATE OR REPLACE PROCEDURE audit_schema_change(
                p_change_type VARCHAR(50),
                p_object_name VARCHAR(255),
                p_change_description TEXT,
                p_change_ticket VARCHAR(50),
                p_performed_by VARCHAR(255)
            )
            LANGUAGE plpgsql
            AS $$
            BEGIN
                INSERT INTO schema_change_log (
                    change_type,
                    object_name,
                    change_description,
                    change_ticket,
                    performed_by,
                    performed_at
                ) VALUES (
                    p_change_type,
                    p_object_name,
                    p_change_description,
                    p_change_ticket,
                    p_performed_by,
                    CURRENT_TIMESTAMP
                );
            END;
            $$;
        </createProcedure>
    </changeSet>

</databaseChangeLog>
"""
        
        # Database deployment script
        db_deployment_script = """
#!/bin/bash
# SOC2 Compliant Database Deployment Script

set -euo pipefail

# Variables
CHANGE_TICKET="${1:-}"
ENVIRONMENT="${2:-staging}"
DRY_RUN="${3:-true}"

# Validate inputs
if [[ -z "$CHANGE_TICKET" ]]; then
    echo "Error: Change ticket number required"
    echo "Usage: $0 CHANGE-XXXX [environment] [dry-run]"
    exit 1
fi

# Validate change ticket
TICKET_STATUS=$(curl -s "https://itsm.company.com/api/tickets/${CHANGE_TICKET}" | jq -r '.status')
if [[ "$TICKET_STATUS" != "Approved" ]]; then
    echo "Error: Change ticket ${CHANGE_TICKET} is not approved"
    exit 1
fi

# Create backup before changes
echo "Creating database backup..."
BACKUP_FILE="backup_${ENVIRONMENT}_$(date +%Y%m%d_%H%M%S).sql"
pg_dump -h ${DB_HOST} -U ${DB_USER} -d ${DB_NAME} > "/backups/${BACKUP_FILE}"

# Log deployment start
curl -X POST https://audit-api.company.com/database-changes \
  -H "Content-Type: application/json" \
  -d "{
    \"environment\": \"${ENVIRONMENT}\",
    \"change_ticket\": \"${CHANGE_TICKET}\",
    \"backup_file\": \"${BACKUP_FILE}\",
    \"started_at\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
    \"initiated_by\": \"${USER}\"
  }"

# Run Liquibase update
if [[ "$DRY_RUN" == "true" ]]; then
    echo "Running in dry-run mode..."
    liquibase \
        --url="jdbc:postgresql://${DB_HOST}:5432/${DB_NAME}" \
        --username="${DB_USER}" \
        --password="${DB_PASSWORD}" \
        --changeLogFile="changelog.xml" \
        updateSQL > "changes_${CHANGE_TICKET}.sql"
    
    echo "SQL to be executed:"
    cat "changes_${CHANGE_TICKET}.sql"
else
    echo "Applying database changes..."
    liquibase \
        --url="jdbc:postgresql://${DB_HOST}:5432/${DB_NAME}" \
        --username="${DB_USER}" \
        --password="${DB_PASSWORD}" \
        --changeLogFile="changelog.xml" \
        update \
        --tag="${CHANGE_TICKET}"
fi

# Verify changes
echo "Verifying database changes..."
liquibase \
    --url="jdbc:postgresql://${DB_HOST}:5432/${DB_NAME}" \
    --username="${DB_USER}" \
    --password="${DB_PASSWORD}" \
    --changeLogFile="changelog.xml" \
    status --verbose

# Run post-deployment tests
echo "Running post-deployment tests..."
./scripts/db-smoke-tests.sh

echo "Database deployment completed successfully"
"""
        
        return {
            'liquibase_config': liquibase_config,
            'deployment_script': db_deployment_script,
            'change_log_table': """
                CREATE TABLE IF NOT EXISTS schema_change_log (
                    id SERIAL PRIMARY KEY,
                    change_type VARCHAR(50) NOT NULL,
                    object_name VARCHAR(255) NOT NULL,
                    change_description TEXT,
                    change_ticket VARCHAR(50) NOT NULL,
                    performed_by VARCHAR(255) NOT NULL,
                    performed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    rollback_performed BOOLEAN DEFAULT FALSE,
                    rollback_at TIMESTAMP,
                    rollback_by VARCHAR(255)
                );
                
                CREATE INDEX idx_change_ticket ON schema_change_log(change_ticket);
                CREATE INDEX idx_performed_at ON schema_change_log(performed_at);
            """
        }
```

## Implementation Validation

### Control Testing Framework
```python
class ControlValidator:
    def __init__(self):
        self.test_results = []
    
    def validate_access_controls(self):
        """Validate CC6.1 access control implementation"""
        tests = [
            {
                'name': 'MFA Enforcement',
                'test': self._test_mfa_enforcement,
                'expected': 'All users have MFA enabled',
                'criticality': 'High'
            },
            {
                'name': 'Password Policy',
                'test': self._test_password_policy,
                'expected': 'Password policy meets requirements',
                'criticality': 'High'
            },
            {
                'name': 'Account Lockout',
                'test': self._test_account_lockout,
                'expected': 'Accounts lock after 5 failed attempts',
                'criticality': 'Medium'
            },
            {
                'name': 'Session Timeout',
                'test': self._test_session_timeout,
                'expected': 'Sessions timeout after inactivity',
                'criticality': 'Medium'
            },
            {
                'name': 'Privilege Escalation',
                'test': self._test_privilege_escalation,
                'expected': 'No unauthorized privilege escalation',
                'criticality': 'High'
            }
        ]
        
        for test in tests:
            result = test['test']()
            self.test_results.append({
                'control': 'CC6.1',
                'test_name': test['name'],
                'result': result['status'],
                'details': result['details'],
                'evidence': result['evidence'],
                'criticality': test['criticality'],
                'timestamp': datetime.now()
            })
        
        return self.test_results
    
    def _test_mfa_enforcement(self):
        """Test MFA is enforced for all users"""
        # Query identity provider
        users_without_mfa = []
        
        # Example for Okta
        okta_client = self.get_okta_client()
        users = okta_client.list_users()
        
        for user in users:
            factors = okta_client.list_factors(user.id)
            if not factors or all(f.status != 'ACTIVE' for f in factors):
                users_without_mfa.append(user.profile.email)
        
        return {
            'status': 'PASS' if not users_without_mfa else 'FAIL',
            'details': f"Found {len(users_without_mfa)} users without MFA",
            'evidence': {
                'total_users': len(users),
                'users_without_mfa': users_without_mfa,
                'test_date': datetime.now().isoformat()
            }
        }
    
    def generate_validation_report(self):
        """Generate comprehensive validation report"""
        report = {
            'report_date': datetime.now().isoformat(),
            'total_tests': len(self.test_results),
            'passed': len([r for r in self.test_results if r['result'] == 'PASS']),
            'failed': len([r for r in self.test_results if r['result'] == 'FAIL']),
            'results_by_control': {},
            'critical_failures': []
        }
        
        # Group by control
        for result in self.test_results:
            control = result['control']
            if control not in report['results_by_control']:
                report['results_by_control'][control] = []
            
            report['results_by_control'][control].append(result)
            
            # Flag critical failures
            if result['result'] == 'FAIL' and result['criticality'] == 'High':
                report['critical_failures'].append(result)
        
        return report
```

## Best Practices

### Implementation Guidelines
1. **Start with critical controls** - Security and availability first
2. **Document everything** - Implementation steps and decisions
3. **Test thoroughly** - Before considering implemented
4. **Automate validation** - Continuous control testing
5. **Version control** - All configurations and scripts
6. **Least privilege** - Always apply principle
7. **Defense in depth** - Multiple layers of controls

### Common Pitfalls to Avoid
- Implementing controls without testing
- Ignoring control dependencies
- Insufficient documentation
- Manual processes that should be automated
- Overly complex implementations
- Lack of monitoring
- Missing rollback procedures

## Control Implementation Checklist

### Pre-Implementation
- [ ] Control requirements understood
- [ ] Dependencies identified
- [ ] Implementation plan documented
- [ ] Test plan created
- [ ] Rollback plan prepared
- [ ] Stakeholders notified

### Implementation
- [ ] Configuration backed up
- [ ] Changes documented
- [ ] Implementation follows plan
- [ ] Testing conducted
- [ ] Evidence collected
- [ ] Monitoring configured

### Post-Implementation
- [ ] Control effectiveness validated
- [ ] Documentation updated
- [ ] Training provided
- [ ] Monitoring alerts working
- [ ] Evidence archived
- [ ] Lessons learned documented

## Integration Examples

### Terraform Integration
```hcl
# SOC2 compliant infrastructure as code
module "soc2_baseline" {
  source = "./modules/soc2-baseline"
  
  # Access controls (CC6.1)
  mfa_required           = true
  session_timeout        = 900
  password_policy = {
    minimum_length       = 12
    require_uppercase    = true
    require_lowercase    = true
    require_numbers      = true
    require_symbols      = true
    password_history     = 12
    max_age_days        = 90
  }
  
  # Monitoring (CC7.1)
  enable_cloudtrail     = true
  enable_config         = true
  enable_guardduty      = true
  enable_security_hub   = true
  
  # Encryption (CC6.7)
  kms_key_rotation      = true
  s3_encryption         = "AES256"
  ebs_encryption        = true
  
  # Network security (CC6.6)
  enable_vpc_flow_logs  = true
  enable_waf            = true
  enable_shield         = true
}
```

## Useful Resources
- Control implementation guides
- Technology-specific hardening guides
- Compliance automation tools
- Security benchmarks (CIS, NIST)
- Vendor best practices