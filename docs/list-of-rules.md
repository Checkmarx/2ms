# Rules

Here is a complete list of all the rules that are currently implemented.

<!-- table:start -->
| Name | Description | Tags | Validity Check |
| ---- | ---- | ---- | ---- |
| Adafruit-Api-Key | Identified a potential Adafruit API Key, which could lead to unauthorized access to Adafruit services and sensitive data exposure. | api-key |  |
| Adobe-Client-Id | Detected a pattern that resembles an Adobe OAuth Web Client ID, posing a risk of compromised Adobe integrations and data breaches. | client-id |  |
| Adobe-Client-Secret | Discovered a potential Adobe Client Secret, which, if exposed, could allow unauthorized Adobe service access and data manipulation. | client-secret |  |
| Age-Secret-Key | Discovered a potential Age encryption tool secret key, risking data decryption and unauthorized access to sensitive information. | secret-key |  |
| Airtable-Api-Key | Uncovered a possible Airtable API Key, potentially compromising database access and leading to data leakage or alteration. | api-key |  |
| Algolia-Api-Key | Identified an Algolia API Key, which could result in unauthorized search operations and data exposure on Algolia-managed platforms. | api-key |  |
| Alibaba-Access-Key-Id | Detected an Alibaba Cloud AccessKey ID, posing a risk of unauthorized cloud resource access and potential data compromise. | access-key,access-id | V |
| Alibaba-Secret-Key | Discovered a potential Alibaba Cloud Secret Key, potentially allowing unauthorized operations and data access within Alibaba Cloud. | secret-key | V |
| Anthropic-Admin-Api-Key | Detected an Anthropic Admin API Key, risking unauthorized access to administrative functions and sensitive AI model configurations. | api-key |  |
| Anthropic-Api-Key | Identified an Anthropic API Key, which may compromise AI assistant integrations and expose sensitive data to unauthorized access. | api-key |  |
| Asana-Client-Id | Discovered a potential Asana Client ID, risking unauthorized access to Asana projects and sensitive task information. | client-id |  |
| Asana-Client-Secret | Identified an Asana Client Secret, which could lead to compromised project management integrity and unauthorized access. | client-secret |  |
| Atlassian-Api-Token | Detected an Atlassian API token,  |  |  |
|  | posing a threat to project management and  |  |  |
|  | collaboration tool security and data confidentiality. | api-token |  |
| Authenticated-Url | Identify username:password inside URLS | sensitive-url |  |
| Authress-Service-Client-Access-Key | Uncovered a possible Authress Service Client Access Key, which may compromise access control services and sensitive data. | access-token |  |
| Aws-Access-Token | Identified a pattern that may indicate AWS credentials, risking unauthorized cloud resource access and data breaches on AWS platforms. | access-token |  |
| Azure-Ad-Client-Secret | Azure AD Client Secret | client-secret |  |
| Bitbucket-Client-Id | Discovered a potential Bitbucket Client ID, risking unauthorized repository access and potential codebase exposure. | client-id |  |
| Bitbucket-Client-Secret | Discovered a potential Bitbucket Client Secret, posing a risk of compromised code repositories and unauthorized access. | client-secret |  |
| Bittrex-Access-Key | Identified a Bittrex Access Key, which could lead to unauthorized access to cryptocurrency trading accounts and financial loss. | access-key |  |
| Bittrex-Secret-Key | Detected a Bittrex Secret Key, potentially compromising cryptocurrency transactions and financial security. | secret-key |  |
| Beamer-Api-Token | Detected a Beamer API token, potentially compromising content management and exposing sensitive notifications and updates. | api-token |  |
| Codecov-Access-Token | Found a pattern resembling a Codecov Access Token, posing a risk of unauthorized access to code coverage reports and sensitive data. | access-token |  |
| Coinbase-Access-Token | Detected a Coinbase Access Token, posing a risk of unauthorized access to cryptocurrency accounts and financial transactions. | access-token |  |
| Clickhouse-Cloud-Api-Secret-Key | Identified a pattern that may indicate clickhouse cloud API secret key, risking unauthorized clickhouse cloud api access and data breaches on ClickHouse Cloud platforms. | secret-key |  |
| Clojars-Api-Token | Uncovered a possible Clojars API token, risking unauthorized access to Clojure libraries and potential code manipulation. | api-token |  |
| Cloudflare-Api-Key | Detected a Cloudflare API Key, potentially compromising cloud application deployments and operational security. | api-key |  |
| Cloudflare-Global-Api-Key | Detected a Cloudflare Global API Key, potentially compromising cloud application deployments and operational security. | api-key |  |
| Cloudflare-Origin-Ca-Key | Detected a Cloudflare Origin CA Key, potentially compromising cloud application deployments and operational security. | encryption-key |  |
| Cohere-Api-Token | Identified a Cohere Token, posing a risk of unauthorized access to AI services and data manipulation. | api-token |  |
| Confluent-Access-Token | Identified a Confluent Access Token, which could compromise access to streaming data platforms and sensitive data flow. | access-token |  |
| Confluent-Secret-Key | Found a Confluent Secret Key, potentially risking unauthorized operations and data access within Confluent services. | secret-key |  |
| Contentful-Delivery-Api-Token | Discovered a Contentful delivery API token, posing a risk to content management systems and data integrity. | api-token |  |
| Curl-Auth-User | Discovered a potential basic authorization token provided in a curl command, which could compromise the curl accessed resource. | access-token |  |
| Curl-Auth-Header | Discovered a potential authorization token provided in a curl command header, which could compromise the curl accessed resource. | access-token |  |
| Databricks-Api-Token | Uncovered a Databricks API token, which may compromise big data analytics platforms and sensitive data processing. | api-token |  |
| Datadog-Access-Token | Detected a Datadog Access Token, potentially risking monitoring and analytics data exposure and manipulation. | access-token,client-id |  |
| Defined-Networking-Api-Token | Identified a Defined Networking API token, which could lead to unauthorized network operations and data breaches. | api-token |  |
| Digitalocean-Pat | Discovered a DigitalOcean Personal Access Token, posing a threat to cloud infrastructure security and data privacy. | access-token |  |
| Digitalocean-Access-Token | Found a DigitalOcean OAuth Access Token, risking unauthorized cloud resource access and data compromise. | access-token |  |
| Digitalocean-Refresh-Token | Uncovered a DigitalOcean OAuth Refresh Token, which could allow prolonged unauthorized access and resource manipulation. | refresh-token |  |
| Discord-Api-Token | Detected a Discord API key, potentially compromising communication channels and user data privacy on Discord. | api-key,api-token |  |
| Discord-Client-Id | Identified a Discord client ID, which may lead to unauthorized integrations and data exposure in Discord applications. | client-id |  |
| Discord-Client-Secret | Discovered a potential Discord client secret, risking compromised Discord bot integrations and data leaks. | client-secret |  |
| Doppler-Api-Token | Discovered a Doppler API token, posing a risk to environment and secrets management security. | api-token |  |
| Dropbox-Api-Token | Identified a Dropbox API secret, which could lead to unauthorized file access and data breaches in Dropbox storage. | api-token |  |
| Dropbox-Short-Lived-Api-Token | Discovered a Dropbox short-lived API token, posing a risk of temporary but potentially harmful data access and manipulation. | api-token |  |
| Dropbox-Long-Lived-Api-Token | Found a Dropbox long-lived API token, risking prolonged unauthorized access to cloud storage and sensitive data. | api-token |  |
| Droneci-Access-Token | Detected a Droneci Access Token, potentially compromising continuous integration and deployment workflows. | access-token |  |
| Duffel-Api-Token | Uncovered a Duffel API token, which may compromise travel platform integrations and sensitive customer data. | api-token |  |
| Dynatrace-Api-Token | Detected a Dynatrace API token, potentially risking application performance monitoring and data exposure. | api-token |  |
| Easypost-Api-Token | Identified an EasyPost API token, which could lead to unauthorized postal and shipment service access and data exposure. | api-token |  |
| Easypost-Test-Api-Token | Detected an EasyPost test API token, risking exposure of test environments and potentially sensitive shipment data. | api-token |  |
| Etsy-Access-Token | Found an Etsy Access Token, potentially compromising Etsy shop management and customer data. | access-token |  |
| Facebook-Secret | Discovered a Facebook Application secret, posing a risk of unauthorized access to Facebook accounts and personal data exposure. | client-secret |  |
| Facebook-Access-Token | Discovered a Facebook Access Token, posing a risk of unauthorized access to Facebook accounts and personal data exposure. | access-token |  |
| Facebook-Page-Access-Token | Discovered a Facebook Page Access Token, posing a risk of unauthorized access to Facebook accounts and personal data exposure. | access-token |  |
| Fastly-Api-Token | Uncovered a Fastly API key, which may compromise CDN and edge cloud services, leading to content delivery and security issues. | api-token,api-key |  |
| Finicity-Client-Secret | Identified a Finicity Client Secret, which could lead to compromised financial service integrations and data breaches. | client-secret |  |
| Finicity-Api-Token | Detected a Finicity API token, potentially risking financial data access and unauthorized financial operations. | api-token |  |
| Flickr-Access-Token | Discovered a Flickr Access Token, posing a risk of unauthorized photo management and potential data leakage. | access-token |  |
| Finnhub-Access-Token | Found a Finnhub Access Token, risking unauthorized access to financial market data and analytics. | access-token |  |
| Flutterwave-Public-Key | Detected a Finicity Public Key, potentially exposing public cryptographic operations and integrations. | public-key |  |
| Flutterwave-Secret-Key | Identified a Flutterwave Secret Key, risking unauthorized financial transactions and data breaches. | secret-key |  |
| Flutterwave-Encryption-Key | Uncovered a Flutterwave Encryption Key, which may compromise payment processing and sensitive financial information. | encryption-key |  |
| Flyio-Access-Token | Uncovered a Fly.io API key | access-token |  |
| Frameio-Api-Token | Found a Frame.io API token, potentially compromising video collaboration and project management. | api-token |  |
| Freemius-Secret-Key | Detected a Freemius secret key, potentially exposing sensitive information. | secret-key |  |
| Freshbooks-Access-Token | Discovered a Freshbooks Access Token, posing a risk to accounting software access and sensitive financial data exposure. | access-token |  |
| Gcp-Api-Key | Uncovered a GCP API key, which could lead to unauthorized access to Google Cloud services and data breaches. | api-key | V |
| Generic-Api-Key | Detected a Generic API Key, potentially exposing access to various services and sensitive operations. | api-key |  |
| Github-Pat | Uncovered a GitHub Personal Access Token, potentially leading to unauthorized repository access and sensitive content exposure. | access-token | V |
| Github-Fine-Grained-Pat | Found a GitHub Fine-Grained Personal Access Token, risking unauthorized repository access and code manipulation. | access-token | V |
| Github-Oauth | Discovered a GitHub OAuth Access Token, posing a risk of compromised GitHub account integrations and data leaks. | access-token |  |
| Github-App-Token | Identified a GitHub App Token, which may compromise GitHub application integrations and source code security. | access-token |  |
| Github-Refresh-Token | Detected a GitHub Refresh Token, which could allow prolonged unauthorized access to GitHub services. | refresh-token |  |
| Gitlab-Cicd-Job-Token | Identified a GitLab CI/CD Job Token, potential access to projects and some APIs on behalf of a user while the CI job is running. | access-token |  |
| Gitlab-Deploy-Token | Identified a GitLab Deploy Token, risking access to repositories, packages and containers with write access. | access-token |  |
| Gitlab-Feature-Flag-Client-Token | Identified a GitLab feature flag client token, risks exposing user lists and features flags used by an application. | access-token |  |
| Gitlab-Feed-Token | Identified a GitLab feed token, risking exposure of user data. | access-token |  |
| Gitlab-Incoming-Mail-Token | Identified a GitLab incoming mail token, risking manipulation of data sent by mail. | access-token |  |
| Gitlab-Kubernetes-Agent-Token | Identified a GitLab Kubernetes Agent token, risking access to repos and registry of projects connected via agent. | access-token |  |
| Gitlab-Oauth-App-Secret | Identified a GitLab OIDC Application Secret, risking access to apps using GitLab as authentication provider. | secret-key |  |
| Gitlab-Pat | Identified a GitLab Personal Access Token, risking unauthorized access to GitLab repositories and codebase exposure. | access-token | V |
| Gitlab-Pat-Routable | Identified a GitLab Personal Access Token (routable), risking unauthorized access to GitLab repositories and codebase exposure. | access-token |  |
| Gitlab-Ptt | Found a GitLab Pipeline Trigger Token, potentially compromising continuous integration workflows and project security. | trigger-token |  |
| Gitlab-Rrt | Discovered a GitLab Runner Registration Token, posing a risk to CI/CD pipeline integrity and unauthorized access. | registration-token |  |
| Gitlab-Runner-Authentication-Token | Discovered a GitLab Runner Authentication Token, posing a risk to CI/CD pipeline integrity and unauthorized access. | access-token |  |
| Gitlab-Runner-Authentication-Token-Routable | Discovered a GitLab Runner Authentication Token (Routable), posing a risk to CI/CD pipeline integrity and unauthorized access. | access-token |  |
| Gitlab-Scim-Token | Discovered a GitLab SCIM Token, posing a risk to unauthorized access for a organization or instance. | access-token |  |
| Gitlab-Session-Cookie | Discovered a GitLab Session Cookie, posing a risk to unauthorized access to a user account. | access-token |  |
| Gitter-Access-Token | Uncovered a Gitter Access Token, which may lead to unauthorized access to chat and communication services. | access-token |  |
| Gocardless-Api-Token | Detected a GoCardless API token, potentially risking unauthorized direct debit payment operations and financial data exposure. | api-token |  |
| Grafana-Api-Key | Identified a Grafana API key, which could compromise monitoring dashboards and sensitive data analytics. | api-key |  |
| Grafana-Cloud-Api-Token | Found a Grafana cloud API token, risking unauthorized access to cloud-based monitoring services and data exposure. | api-token |  |
| Grafana-Service-Account-Token | Discovered a Grafana service account token, posing a risk of compromised monitoring services and data integrity. | access-token |  |
| Hashicorp-Tf-Api-Token | Uncovered a HashiCorp Terraform user/org API token, which may lead to unauthorized infrastructure management and security breaches. | api-token |  |
| Hashicorp-Tf-Password | Identified a HashiCorp Terraform password field, risking unauthorized infrastructure configuration and security breaches. | password |  |
| Heroku-Api-Key | Detected a Heroku API Key, potentially compromising cloud application deployments and operational security. | api-key |  |
| Heroku-Api-Key-V2 | Detected a Heroku API Key, potentially compromising cloud application deployments and operational security. | api-key |  |
| Hubspot-Api-Key | Found a HubSpot API Token, posing a risk to CRM data integrity and unauthorized marketing operations. | api-token,api-key |  |
| Huggingface-Access-Token | Discovered a Hugging Face Access token, which could lead to unauthorized access to AI models and sensitive data. | access-token |  |
| Huggingface-Organization-Api-Token | Uncovered a Hugging Face Organization API token, potentially compromising AI organization accounts and associated data. | api-token |  |
| Infracost-Api-Token | Detected an Infracost API Token, risking unauthorized access to cloud cost estimation tools and financial data. | api-token |  |
| Intercom-Api-Key | Identified an Intercom API Token, which could compromise customer communication channels and data privacy. | api-token,api-key |  |
| Intra42-Client-Secret | Found a Intra42 client secret, which could lead to unauthorized access to the 42School API and sensitive data. | client-secret |  |
| Jfrog-Api-Key | Found a JFrog API Key, posing a risk of unauthorized access to software artifact repositories and build pipelines. | api-key |  |
| Jfrog-Identity-Token | Discovered a JFrog Identity Token, potentially compromising access to JFrog services and sensitive software artifacts. | access-token |  |
| jwt | Uncovered a JSON Web Token, which may lead to unauthorized access to web applications and sensitive user data. | access-token |  |
| Jwt-Base64 | Detected a Base64-encoded JSON Web Token, posing a risk of exposing encoded authentication and data exchange information. | access-token |  |
| Kraken-Access-Token | Identified a Kraken Access Token, potentially compromising cryptocurrency trading accounts and financial security. | access-token |  |
| Kubernetes-Secret-Yaml | Possible Kubernetes Secret detected, posing a risk of leaking credentials/tokens from your deployments | secret-key |  |
| Kucoin-Access-Token | Found a Kucoin Access Token, risking unauthorized access to cryptocurrency exchange services and transactions. | access-token |  |
| Kucoin-Secret-Key | Discovered a Kucoin Secret Key, which could lead to compromised cryptocurrency operations and financial data breaches. | secret-key |  |
| Launchdarkly-Access-Token | Uncovered a Launchdarkly Access Token, potentially compromising feature flag management and application functionality. | access-token |  |
| Linear-Api-Key | Detected a Linear API Token, posing a risk to project management tools and sensitive task data. | api-token,api-key |  |
| Linear-Client-Secret | Identified a Linear Client Secret, which may compromise secure integrations and sensitive project management data. | client-secret |  |
| Linkedin-Client-Id | Found a LinkedIn Client ID, risking unauthorized access to LinkedIn integrations and professional data exposure. | client-id |  |
| Linkedin-Client-Secret | Discovered a LinkedIn Client secret, potentially compromising LinkedIn application integrations and user data. | client-secret |  |
| Lob-Api-Key | Uncovered a Lob API Key, which could lead to unauthorized access to mailing and address verification services. | api-key |  |
| Lob-Pub-Api-Key | Detected a Lob Publishable API Key, posing a risk of exposing mail and print service integrations. | api-key |  |
| Mailchimp-Api-Key | Identified a Mailchimp API key, potentially compromising email marketing campaigns and subscriber data. | api-key |  |
| Mailgun-Pub-Key | Discovered a Mailgun public validation key, which could expose email verification processes and associated data. | public-key |  |
| Mailgun-Private-Api-Token | Found a Mailgun private API token, risking unauthorized email service operations and data breaches. | private-key |  |
| Mailgun-Signing-Key | Uncovered a Mailgun webhook signing key, potentially compromising email automation and data integrity. | api-key |  |
| Mapbox-Api-Token | Detected a MapBox API token, posing a risk to geospatial services and sensitive location data exposure. | api-token |  |
| Mattermost-Access-Token | Identified a Mattermost Access Token, which may compromise team communication channels and data privacy. | access-token |  |
| Maxmind-License-Key | Discovered a potential MaxMind license key. | api-key |  |
| Cisco-Meraki-Api-Key | Cisco Meraki is a cloud-managed IT solution that provides networking, security, and device management through an easy-to-use interface. | api-key |  |
| Messagebird-Api-Token | Found a MessageBird API token, risking unauthorized access to communication platforms and message data. | api-token |  |
| Messagebird-Client-Id | Discovered a MessageBird client ID, potentially compromising API integrations and sensitive communication data. | client-id |  |
| Netlify-Access-Token | Detected a Netlify Access Token, potentially compromising web hosting services and site management. | access-token |  |
| New-Relic-User-Api-Key | Discovered a New Relic user API Key, which could lead to compromised application insights and performance monitoring. | api-key |  |
| New-Relic-User-Api-Id | Found a New Relic user API ID, posing a risk to application monitoring services and data integrity. | access-id |  |
| New-Relic-Browser-Api-Token | Identified a New Relic ingest browser API token, risking unauthorized access to application performance data and analytics. | api-token |  |
| New-Relic-Insert-Key | Discovered a New Relic insight insert key, compromising data injection into the platform. | api-key |  |
| Notion-Api-Token | Notion API token | api-token |  |
| Npm-Access-Token | Uncovered an npm access token, potentially compromising package management and code repository access. | access-token |  |
| Nuget-Config-Password | Identified a password within a Nuget config file, potentially compromising package management access. | password |  |
| Nytimes-Access-Token | Detected a Nytimes Access Token, risking unauthorized access to New York Times APIs and content services. | access-token |  |
| Octopus-Deploy-Api-Key | Discovered a potential Octopus Deploy API key, risking application deployments and operational security. | api-key |  |
| Okta-Access-Token | Identified an Okta Access Token, which may compromise identity management services and user authentication data. | access-token |  |
| 1Password-Secret-Key | Uncovered a possible 1Password secret key, potentially compromising access to secrets in vaults. | private-key |  |
| 1Password-Service-Account-Token | Uncovered a possible 1Password service account token, potentially compromising access to secrets in vaults. | access-token |  |
| Openai-Api-Key | Found an OpenAI API Key, posing a risk of unauthorized access to AI services and data manipulation. | api-key |  |
| Openshift-User-Token | Found an OpenShift user token, potentially compromising an OpenShift/Kubernetes cluster. | access-token |  |
| Perplexity-Api-Key | Detected a Perplexity API key, which could lead to unauthorized access to Perplexity AI services and data exposure. | api-key |  |
| Plaid-Client-Id | Uncovered a Plaid Client ID, which could lead to unauthorized financial service integrations and data breaches. | client-id |  |
| Plaid-Secret-Key | Detected a Plaid Secret key, risking unauthorized access to financial accounts and sensitive transaction data. | secret-key |  |
| Plaid-Api-Token | Discovered a Plaid API Token, potentially compromising financial data aggregation and banking services. | api-token |  |
| Planetscale-Password | Discovered a PlanetScale password, which could lead to unauthorized database operations and data breaches. | password |  |
| Planetscale-Api-Token | Identified a PlanetScale API token, potentially compromising database management and operations. | api-token |  |
| Planetscale-Oauth-Token | Found a PlanetScale OAuth token, posing a risk to database access control and sensitive data integrity. | access-token |  |
| Postman-Api-Token | Uncovered a Postman API token, potentially compromising API testing and development workflows. | api-token |  |
| Prefect-Api-Token | Detected a Prefect API token, risking unauthorized access to workflow management and automation services. | api-token |  |
| Privateai-Api-Token | Identified a PrivateAI Token, posing a risk of unauthorized access to AI services and data manipulation. | api-token |  |
| Private-Key | Identified a Private Key, which may compromise cryptographic security and sensitive data encryption. | private-key |  |
| Pulumi-Api-Token | Found a Pulumi API token, posing a risk to infrastructure as code services and cloud resource management. | api-token |  |
| Pypi-Upload-Token | Discovered a PyPI upload token, potentially compromising Python package distribution and repository integrity. | upload-token |  |
| Rapidapi-Access-Token | Uncovered a RapidAPI Access Token, which could lead to unauthorized access to various APIs and data services. | access-token |  |
| Readme-Api-Token | Detected a Readme API token, risking unauthorized documentation management and content exposure. | api-token |  |
| Rubygems-Api-Token | Identified a Rubygem API token, potentially compromising Ruby library distribution and package management. | api-token |  |
| Scalingo-Api-Token | Found a Scalingo API token, posing a risk to cloud platform services and application deployment security. | api-token |  |
| Sendbird-Access-Id | Discovered a Sendbird Access ID, which could compromise chat and messaging platform integrations. | access-id |  |
| Sendbird-Access-Token | Uncovered a Sendbird Access Token, potentially risking unauthorized access to communication services and user data. | access-token |  |
| Sendgrid-Api-Token | Detected a SendGrid API token, posing a risk of unauthorized email service operations and data exposure. | api-token |  |
| Sendinblue-Api-Token | Identified a Sendinblue API token, which may compromise email marketing services and subscriber data privacy. | api-token |  |
| Sentry-Access-Token | Found a Sentry.io Access Token (old format), risking unauthorized access to error tracking services and sensitive application data. | access-token |  |
| Sentry-Org-Token | Found a Sentry.io Organization Token, risking unauthorized access to error tracking services and sensitive application data. | access-token |  |
| Sentry-User-Token | Found a Sentry.io User Token, risking unauthorized access to error tracking services and sensitive application data. | access-token |  |
| Settlemint-Application-Access-Token | Found a Settlemint Application Access Token. | access-token |  |
| Settlemint-Personal-Access-Token | Found a Settlemint Personal Access Token. | access-token |  |
| Settlemint-Service-Access-Token | Found a Settlemint Service Access Token. | access-token |  |
| Shippo-Api-Token | Discovered a Shippo API token, potentially compromising shipping services and customer order data. | api-token |  |
| Shopify-Access-Token | Uncovered a Shopify access token, which could lead to unauthorized e-commerce platform access and data breaches. | access-token |  |
| Shopify-Custom-Access-Token | Detected a Shopify custom access token, potentially compromising custom app integrations and e-commerce data security. | access-token |  |
| Shopify-Private-App-Access-Token | Identified a Shopify private app access token, risking unauthorized access to private app data and store operations. | access-token |  |
| Shopify-Shared-Secret | Found a Shopify shared secret, posing a risk to application authentication and e-commerce platform security. | public-secret |  |
| Sidekiq-Secret | Discovered a Sidekiq Secret, which could lead to compromised background job processing and application data breaches. | secret-key |  |
| Sidekiq-Sensitive-Url | Uncovered a Sidekiq Sensitive URL, potentially exposing internal job queues and sensitive operation details. | sensitive-url |  |
| Slack-Bot-Token | Identified a Slack Bot token, which may compromise bot integrations and communication channel security. | access-token |  |
| Slack-App-Token | Detected a Slack App-level token, risking unauthorized access to Slack applications and workspace data. | access-token |  |
| Slack-Legacy-Token | Detected a Slack Legacy token, risking unauthorized access to older Slack integrations and user data. | access-token |  |
| Slack-User-Token | Found a Slack User token, posing a risk of unauthorized user impersonation and data access within Slack workspaces. | access-token |  |
| Slack-Config-Access-Token | Found a Slack Configuration access token, posing a risk to workspace configuration and sensitive data access. | access-token |  |
| Slack-Config-Refresh-Token | Discovered a Slack Configuration refresh token, potentially allowing prolonged unauthorized access to configuration settings. | refresh-token |  |
| Slack-Legacy-Bot-Token | Uncovered a Slack Legacy bot token, which could lead to compromised legacy bot operations and data exposure. | access-token |  |
| Slack-Legacy-Workspace-Token | Identified a Slack Legacy Workspace token, potentially compromising access to workspace data and legacy features. | access-token |  |
| Slack-Webhook-Url | Discovered a Slack Webhook, which could lead to unauthorized message posting and data leakage in Slack channels. | webhook |  |
| Stripe-Access-Token | Found a Stripe Access Token, posing a risk to payment processing services and sensitive financial data. | access-token |  |
| Square-Access-Token | Detected a Square Access Token, risking unauthorized payment processing and financial transaction exposure. | access-token |  |
| Squarespace-Access-Token | Identified a Squarespace Access Token, which may compromise website management and content control on Squarespace. | access-token |  |
| Sumologic-Access-Id | Discovered a SumoLogic Access ID, potentially compromising log management services and data analytics integrity. | access-id |  |
| Sumologic-Access-Token | Uncovered a SumoLogic Access Token, which could lead to unauthorized access to log data and analytics insights. | access-token |  |
| Snyk-Api-Token | Uncovered a Snyk API token, potentially compromising software vulnerability scanning and code security. | api-key |  |
| Microsoft-Teams-Webhook | Uncovered a Microsoft Teams Webhook, which could lead to unauthorized access to team collaboration tools and data leaks. | webhook |  |
| Telegram-Bot-Api-Token | Detected a Telegram Bot API Token, risking unauthorized bot operations and message interception on Telegram. | api-token |  |
| Travisci-Access-Token | Identified a Travis CI Access Token, potentially compromising continuous integration services and codebase security. | access-token |  |
| Twilio-Api-Key | Found a Twilio API Key, posing a risk to communication services and sensitive customer interaction data. | api-key |  |
| Twitch-Api-Token | Discovered a Twitch API token, which could compromise streaming services and account integrations. | api-token |  |
| Twitter-Api-Key | Identified a Twitter API Key, which may compromise Twitter application integrations and user data security. | api-key |  |
| Twitter-Api-Secret | Found a Twitter API Secret, risking the security of Twitter app integrations and sensitive data access. | api-key |  |
| Twitter-Access-Token | Detected a Twitter Access Token, posing a risk of unauthorized account operations and social media data exposure. | access-token |  |
| Twitter-Access-Secret | Uncovered a Twitter Access Secret, potentially risking unauthorized Twitter integrations and data breaches. | public-secret |  |
| Twitter-Bearer-Token | Discovered a Twitter Bearer Token, potentially compromising API access and data retrieval from Twitter. | api-token |  |
| Typeform-Api-Token | Uncovered a Typeform API token, which could lead to unauthorized survey management and data collection. | api-token |  |
| Vault-Batch-Token | Detected a Vault Batch Token, risking unauthorized access to secret management services and sensitive data. | api-token |  |
| Vault-Service-Token | Identified a Vault Service Token, potentially compromising infrastructure security and access to sensitive credentials. | api-token |  |
| Yandex-Api-Key | Discovered a Yandex API Key, which could lead to unauthorized access to Yandex services and data manipulation. | api-key |  |
| Yandex-Aws-Access-Token | Uncovered a Yandex AWS Access Token, potentially compromising cloud resource access and data security on Yandex Cloud. | access-token |  |
| Yandex-Access-Token | Found a Yandex Access Token, posing a risk to Yandex service integrations and user data privacy. | access-token |  |
| Zendesk-Secret-Key | Detected a Zendesk Secret Key, risking unauthorized access to customer support services and sensitive ticketing data. | secret-key |  |
<!-- table:end -->
