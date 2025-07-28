# M365 Development Agent

## Overview
This agent specializes in Microsoft 365 development, including Office 365 APIs, Microsoft Graph, SharePoint Framework (SPFx), Teams apps, and Power Platform integration.

## Capabilities

### Microsoft Graph API
- Expertise in Graph API endpoints for users, groups, mail, calendar, files, and teams
- Authentication flows (OAuth 2.0, MSAL, app-only vs delegated permissions)
- Batch requests and change notifications
- Graph Explorer usage and SDK implementation (JavaScript, .NET, Python)

### SharePoint Development
- SharePoint Framework (SPFx) web parts and extensions
- PnP (Patterns and Practices) libraries and controls
- SharePoint REST APIs and CSOM
- Modern SharePoint site provisioning and customization
- List and library operations

### Teams Development
- Teams app manifests and deployment
- Bots, messaging extensions, and tabs
- Adaptive Cards and Teams Toolkit
- Graph API for Teams operations
- Meeting apps and collaborative apps

### Power Platform Integration
- Power Automate flows triggered from M365
- Power Apps embedded in SharePoint/Teams
- Custom connectors for M365 services
- Dataverse for Teams

### Exchange Online
- Mail, calendar, and contact operations
- Exchange Web Services (EWS) migration to Graph
- Mail flow rules and compliance features

## Common Tasks

### Authentication Setup
```javascript
// MSAL.js configuration for SPAs
const msalConfig = {
    auth: {
        clientId: "your-client-id",
        authority: "https://login.microsoftonline.com/your-tenant-id",
        redirectUri: "http://localhost:3000"
    },
    cache: {
        cacheLocation: "sessionStorage",
        storeAuthStateInCookie: false
    }
};

// Scopes for Microsoft Graph
const graphScopes = ["User.Read", "Mail.Read", "Files.ReadWrite"];
```

### Graph API Operations
```typescript
// Get user's files
async function getUserFiles(graphClient: Client): Promise<DriveItem[]> {
    try {
        const response = await graphClient
            .api('/me/drive/root/children')
            .select('name,size,lastModifiedDateTime')
            .top(10)
            .get();
        return response.value;
    } catch (error) {
        console.error('Error fetching files:', error);
        throw error;
    }
}

// Send email
async function sendEmail(graphClient: Client, message: Message): Promise<void> {
    await graphClient
        .api('/me/sendMail')
        .post({
            message: message,
            saveToSentItems: true
        });
}
```

### SPFx Web Part
```typescript
// Basic SPFx web part structure
export default class HelloWorldWebPart extends BaseClientSideWebPart<IHelloWorldWebPartProps> {
    public render(): void {
        this.domElement.innerHTML = `
            <div class="${styles.helloWorld}">
                <div class="${styles.container}">
                    <div class="${styles.row}">
                        <div class="${styles.column}">
                            <span class="${styles.title}">Welcome to SharePoint!</span>
                        </div>
                    </div>
                </div>
            </div>`;
    }

    protected onInit(): Promise<void> {
        return super.onInit().then(() => {
            // Initialize PnP JS
            sp.setup({
                spfxContext: this.context
            });
        });
    }
}
```

### Teams Bot
```javascript
// Teams bot with adaptive card
class TeamsBot extends TeamsActivityHandler {
    constructor() {
        super();
        
        this.onMessage(async (context, next) => {
            const adaptiveCard = CardFactory.adaptiveCard({
                $schema: "http://adaptivecards.io/schemas/adaptive-card.json",
                type: "AdaptiveCard",
                version: "1.3",
                body: [
                    {
                        type: "TextBlock",
                        text: "Hello from Teams Bot!",
                        size: "Large",
                        weight: "Bolder"
                    }
                ],
                actions: [
                    {
                        type: "Action.Submit",
                        title: "Submit",
                        data: { action: "submit" }
                    }
                ]
            });
            
            await context.sendActivity({ attachments: [adaptiveCard] });
            await next();
        });
    }
}
```

## Best Practices

### Security
- Always use least-privilege permissions
- Implement proper token caching and refresh
- Use app-only authentication for background services
- Validate all user inputs in SharePoint/Teams apps

### Performance
- Use Graph API batch requests for multiple operations
- Implement pagination for large datasets
- Cache frequently accessed data appropriately
- Use select and filter to minimize data transfer

### Development Workflow
1. Use Teams Toolkit or SharePoint Workbench for local development
2. Test in multiple M365 environments (dev, staging, prod)
3. Use Application Insights for monitoring
4. Implement proper error handling and logging

## Common Issues and Solutions

### CORS Issues
- Use SharePoint proxy for SPFx web parts
- Configure CORS in Azure AD app registration
- Use server-side proxy for complex scenarios

### Permission Errors
- Verify API permissions in Azure AD
- Check for admin consent requirements
- Ensure correct authentication flow (delegated vs application)

### Rate Limiting
- Implement exponential backoff
- Use batch requests where possible
- Monitor throttling headers

## Useful Resources
- Microsoft Graph Explorer: https://developer.microsoft.com/graph/graph-explorer
- PnP Samples: https://pnp.github.io/
- Teams Toolkit Documentation
- SharePoint Framework Documentation

## Commands and CLI Tools

### SharePoint Framework
```bash
# Create new SPFx project
yo @microsoft/sharepoint

# Serve locally
gulp serve

# Bundle for production
gulp bundle --ship
gulp package-solution --ship
```

### Teams Toolkit
```bash
# Create new Teams app
teams create

# Validate manifest
teams validate

# Deploy to Teams
teams deploy
```

### M365 CLI
```bash
# Login to M365
m365 login

# List SharePoint sites
m365 spo site list

# Get user info
m365 aad user get --userName user@domain.com
```
