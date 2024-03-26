# Rules

Here is a complete list of all the rules that are currently implemented.

<!-- table:start -->
| Name | Description | Tags | Validity Check |
| ---- | ---- | ---- | ---- |
| adafruit-api-key | Identified a potential Adafruit API Key, which could lead to unauthorized access to Adafruit services and sensitive data exposure. | api-key |  |
| adobe-client-id | Detected a pattern that resembles an Adobe OAuth Web Client ID, posing a risk of compromised Adobe integrations and data breaches. | client-id |  |
| adobe-client-secret | Discovered a potential Adobe Client Secret, which, if exposed, could allow unauthorized Adobe service access and data manipulation. | client-secret |  |
| age secret key | Discovered a potential Age encryption tool secret key, risking data decryption and unauthorized access to sensitive information. | secret-key |  |
| airtable-api-key | Uncovered a possible Airtable API Key, potentially compromising database access and leading to data leakage or alteration. | api-key |  |
| algolia-api-key | Identified an Algolia API Key, which could result in unauthorized search operations and data exposure on Algolia-managed platforms. | api-key |  |
| alibaba-access-key-id | Detected an Alibaba Cloud AccessKey ID, posing a risk of unauthorized cloud resource access and potential data compromise. | access-key,access-id | V |
| alibaba-secret-key | Discovered a potential Alibaba Cloud Secret Key, potentially allowing unauthorized operations and data access within Alibaba Cloud. | secret-key | V |
| asana-client-id | Discovered a potential Asana Client ID, risking unauthorized access to Asana projects and sensitive task information. | client-id |  |
| asana-client-secret | Identified an Asana Client Secret, which could lead to compromised project management integrity and unauthorized access. | client-secret |  |
| atlassian-api-token | Detected an Atlassian API token, posing a threat to project management and collaboration tool security and data confidentiality. | api-token |  |
| authress-service-client-access-key | Uncovered a possible Authress Service Client Access Key, which may compromise access control services and sensitive data. | access-token |  |
| aws-access-token | Identified a pattern that may indicate AWS credentials, risking unauthorized cloud resource access and data breaches on AWS platforms. | access-token |  |
| bitbucket-client-id | Discovered a potential Bitbucket Client ID, risking unauthorized repository access and potential codebase exposure. | client-id |  |
| bitbucket-client-secret | Discovered a potential Bitbucket Client Secret, posing a risk of compromised code repositories and unauthorized access. | client-secret |  |
| bittrex-access-key | Identified a Bittrex Access Key, which could lead to unauthorized access to cryptocurrency trading accounts and financial loss. | access-key |  |
| bittrex-secret-key | Detected a Bittrex Secret Key, potentially compromising cryptocurrency transactions and financial security. | secret-key |  |
| beamer-api-token | Detected a Beamer API token, potentially compromising content management and exposing sensitive notifications and updates. | api-token |  |
| codecov-access-token | Found a pattern resembling a Codecov Access Token, posing a risk of unauthorized access to code coverage reports and sensitive data. | access-token |  |
| coinbase-access-token | Detected a Coinbase Access Token, posing a risk of unauthorized access to cryptocurrency accounts and financial transactions. | access-token |  |
| clojars-api-token | Uncovered a possible Clojars API token, risking unauthorized access to Clojure libraries and potential code manipulation. | api-token |  |
| confluent-access-token | Identified a Confluent Access Token, which could compromise access to streaming data platforms and sensitive data flow. | access-token |  |
| confluent-secret-key | Found a Confluent Secret Key, potentially risking unauthorized operations and data access within Confluent services. | secret-key |  |
| contentful-delivery-api-token | Discovered a Contentful delivery API token, posing a risk to content management systems and data integrity. | api-token |  |
| databricks-api-token | Uncovered a Databricks API token, which may compromise big data analytics platforms and sensitive data processing. | api-token |  |
| datadog-access-token | Detected a Datadog Access Token, potentially risking monitoring and analytics data exposure and manipulation. | access-token,client-id |  |
| defined-networking-api-token | Identified a Defined Networking API token, which could lead to unauthorized network operations and data breaches. | api-token |  |
| digitalocean-pat | Discovered a DigitalOcean Personal Access Token, posing a threat to cloud infrastructure security and data privacy. | access-token |  |
| digitalocean-access-token | Found a DigitalOcean OAuth Access Token, risking unauthorized cloud resource access and data compromise. | access-token |  |
| digitalocean-refresh-token | Uncovered a DigitalOcean OAuth Refresh Token, which could allow prolonged unauthorized access and resource manipulation. | refresh-token |  |
| discord-api-token | Detected a Discord API key, potentially compromising communication channels and user data privacy on Discord. | api-key,api-token |  |
| discord-client-id | Identified a Discord client ID, which may lead to unauthorized integrations and data exposure in Discord applications. | client-id |  |
| discord-client-secret | Discovered a potential Discord client secret, risking compromised Discord bot integrations and data leaks. | client-secret |  |
| doppler-api-token | Discovered a Doppler API token, posing a risk to environment and secrets management security. | api-token |  |
| dropbox-api-token | Identified a Dropbox API secret, which could lead to unauthorized file access and data breaches in Dropbox storage. | api-token |  |
| dropbox-short-lived-api-token | Discovered a Dropbox short-lived API token, posing a risk of temporary but potentially harmful data access and manipulation. | api-token |  |
| dropbox-long-lived-api-token | Found a Dropbox long-lived API token, risking prolonged unauthorized access to cloud storage and sensitive data. | api-token |  |
| droneci-access-token | Detected a Droneci Access Token, potentially compromising continuous integration and deployment workflows. | access-token |  |
| duffel-api-token | Uncovered a Duffel API token, which may compromise travel platform integrations and sensitive customer data. | api-token |  |
| dynatrace-api-token | Detected a Dynatrace API token, potentially risking application performance monitoring and data exposure. | api-token |  |
| easypost-api-token | Identified an EasyPost API token, which could lead to unauthorized postal and shipment service access and data exposure. | api-token |  |
| easypost-test-api-token | Detected an EasyPost test API token, risking exposure of test environments and potentially sensitive shipment data. | api-token |  |
| etsy-access-token | Found an Etsy Access Token, potentially compromising Etsy shop management and customer data. | access-token |  |
| facebook | Discovered a Facebook Access Token, posing a risk of unauthorized access to Facebook accounts and personal data exposure. | api-token |  |
| fastly-api-token | Uncovered a Fastly API key, which may compromise CDN and edge cloud services, leading to content delivery and security issues. | api-token,api-key |  |
| finicity-client-secret | Identified a Finicity Client Secret, which could lead to compromised financial service integrations and data breaches. | client-secret |  |
| finicity-api-token | Detected a Finicity API token, potentially risking financial data access and unauthorized financial operations. | api-token |  |
| flickr-access-token | Discovered a Flickr Access Token, posing a risk of unauthorized photo management and potential data leakage. | access-token |  |
| finnhub-access-token | Found a Finnhub Access Token, risking unauthorized access to financial market data and analytics. | access-token |  |
| flutterwave-public-key | Detected a Finicity Public Key, potentially exposing public cryptographic operations and integrations. | public-key |  |
| flutterwave-secret-key | Identified a Flutterwave Secret Key, risking unauthorized financial transactions and data breaches. | secret-key |  |
| flutterwave-encryption-key | Uncovered a Flutterwave Encryption Key, which may compromise payment processing and sensitive financial information. | encryption-key |  |
| frameio-api-token | Found a Frame.io API token, potentially compromising video collaboration and project management. | api-token |  |
| freshbooks-access-token | Discovered a Freshbooks Access Token, posing a risk to accounting software access and sensitive financial data exposure. | access-token |  |
| gcp-api-key | Uncovered a GCP API key, which could lead to unauthorized access to Google Cloud services and data breaches. | api-key |  |
| generic-api-key | Detected a Generic API Key, potentially exposing access to various services and sensitive operations. | api-key |  |
| github-pat | Uncovered a GitHub Personal Access Token, potentially leading to unauthorized repository access and sensitive content exposure. | access-token | V |
| github-fine-grained-pat | Found a GitHub Fine-Grained Personal Access Token, risking unauthorized repository access and code manipulation. | access-token | V |
| github-oauth | Discovered a GitHub OAuth Access Token, posing a risk of compromised GitHub account integrations and data leaks. | access-token |  |
| github-app-token | Identified a GitHub App Token, which may compromise GitHub application integrations and source code security. | access-token |  |
| github-refresh-token | Detected a GitHub Refresh Token, which could allow prolonged unauthorized access to GitHub services. | refresh-token |  |
| gitlab-pat | Identified a GitLab Personal Access Token, risking unauthorized access to GitLab repositories and codebase exposure. | access-token |  |
| gitlab-ptt | Found a GitLab Pipeline Trigger Token, potentially compromising continuous integration workflows and project security. | trigger-token |  |
| gitlab-rrt | Discovered a GitLab Runner Registration Token, posing a risk to CI/CD pipeline integrity and unauthorized access. | registration-token |  |
| gitter-access-token | Uncovered a Gitter Access Token, which may lead to unauthorized access to chat and communication services. | access-token |  |
| gocardless-api-token | Detected a GoCardless API token, potentially risking unauthorized direct debit payment operations and financial data exposure. | api-token |  |
| grafana-api-key | Identified a Grafana API key, which could compromise monitoring dashboards and sensitive data analytics. | api-key |  |
| grafana-cloud-api-token | Found a Grafana cloud API token, risking unauthorized access to cloud-based monitoring services and data exposure. | api-token |  |
| grafana-service-account-token | Discovered a Grafana service account token, posing a risk of compromised monitoring services and data integrity. | access-token |  |
| hashicorp-tf-api-token | Uncovered a HashiCorp Terraform user/org API token, which may lead to unauthorized infrastructure management and security breaches. | api-token |  |
| hashicorp-tf-password | Identified a HashiCorp Terraform password field, risking unauthorized infrastructure configuration and security breaches. | password |  |
| heroku-api-key | Detected a Heroku API Key, potentially compromising cloud application deployments and operational security. | api-key |  |
| hubspot-api-key | Found a HubSpot API Token, posing a risk to CRM data integrity and unauthorized marketing operations. | api-token,api-key |  |
| huggingface-access-token | Discovered a Hugging Face Access token, which could lead to unauthorized access to AI models and sensitive data. | access-token |  |
| huggingface-organization-api-token | Uncovered a Hugging Face Organization API token, potentially compromising AI organization accounts and associated data. | api-token |  |
| infracost-api-token | Detected an Infracost API Token, risking unauthorized access to cloud cost estimation tools and financial data. | api-token |  |
| intercom-api-key | Identified an Intercom API Token, which could compromise customer communication channels and data privacy. | api-token,api-key |  |
| jfrog-api-key | Found a JFrog API Key, posing a risk of unauthorized access to software artifact repositories and build pipelines. | api-key |  |
| jfrog-identity-token | Discovered a JFrog Identity Token, potentially compromising access to JFrog services and sensitive software artifacts. | access-token |  |
| jwt | Uncovered a JSON Web Token, which may lead to unauthorized access to web applications and sensitive user data. | access-token |  |
| jwt-base64 | Detected a Base64-encoded JSON Web Token, posing a risk of exposing encoded authentication and data exchange information. | access-token |  |
| kraken-access-token | Identified a Kraken Access Token, potentially compromising cryptocurrency trading accounts and financial security. | access-token |  |
| kucoin-access-token | Found a Kucoin Access Token, risking unauthorized access to cryptocurrency exchange services and transactions. | access-token |  |
| kucoin-secret-key | Discovered a Kucoin Secret Key, which could lead to compromised cryptocurrency operations and financial data breaches. | secret-key |  |
| launchdarkly-access-token | Uncovered a Launchdarkly Access Token, potentially compromising feature flag management and application functionality. | access-token |  |
| linear-api-key | Detected a Linear API Token, posing a risk to project management tools and sensitive task data. | api-token,api-key |  |
| linear-client-secret | Identified a Linear Client Secret, which may compromise secure integrations and sensitive project management data. | client-secret |  |
| linkedin-client-id | Found a LinkedIn Client ID, risking unauthorized access to LinkedIn integrations and professional data exposure. | client-id |  |
| linkedin-client-secret | Discovered a LinkedIn Client secret, potentially compromising LinkedIn application integrations and user data. | client-secret |  |
| lob-api-key | Uncovered a Lob API Key, which could lead to unauthorized access to mailing and address verification services. | api-key |  |
| lob-pub-api-key | Detected a Lob Publishable API Key, posing a risk of exposing mail and print service integrations. | api-key |  |
| mailchimp-api-key | Identified a Mailchimp API key, potentially compromising email marketing campaigns and subscriber data. | api-key |  |
| mailgun-pub-key | Discovered a Mailgun public validation key, which could expose email verification processes and associated data. | public-key |  |
| mailgun-private-api-token | Found a Mailgun private API token, risking unauthorized email service operations and data breaches. | private-key |  |
| mailgun-signing-key | Uncovered a Mailgun webhook signing key, potentially compromising email automation and data integrity. | api-key |  |
| mapbox-api-token | Detected a MapBox API token, posing a risk to geospatial services and sensitive location data exposure. | api-token |  |
| mattermost-access-token | Identified a Mattermost Access Token, which may compromise team communication channels and data privacy. | access-token |  |
| messagebird-api-token | Found a MessageBird API token, risking unauthorized access to communication platforms and message data. | api-token |  |
| messagebird-client-id | Discovered a MessageBird client ID, potentially compromising API integrations and sensitive communication data. | client-id |  |
| netlify-access-token | Detected a Netlify Access Token, potentially compromising web hosting services and site management. | access-token |  |
| new-relic-user-api-key | Discovered a New Relic user API Key, which could lead to compromised application insights and performance monitoring. | api-key |  |
| new-relic-user-api-id | Found a New Relic user API ID, posing a risk to application monitoring services and data integrity. | access-id |  |
| new-relic-browser-api-token | Identified a New Relic ingest browser API token, risking unauthorized access to application performance data and analytics. | api-token |  |
| npm-access-token | Uncovered an npm access token, potentially compromising package management and code repository access. | access-token |  |
| nytimes-access-token | Detected a Nytimes Access Token, risking unauthorized access to New York Times APIs and content services. | access-token |  |
| okta-access-token | Identified an Okta Access Token, which may compromise identity management services and user authentication data. | access-token |  |
| openai-api-key | Found an OpenAI API Key, posing a risk of unauthorized access to AI services and data manipulation. | api-key |  |
| plaid-client-id | Uncovered a Plaid Client ID, which could lead to unauthorized financial service integrations and data breaches. | client-id |  |
| plaid-secret-key | Detected a Plaid Secret key, risking unauthorized access to financial accounts and sensitive transaction data. | secret-key |  |
| plaid-api-token | Discovered a Plaid API Token, potentially compromising financial data aggregation and banking services. | api-token |  |
| planetscale-password | Discovered a PlanetScale password, which could lead to unauthorized database operations and data breaches. | password |  |
| planetscale-api-token | Identified a PlanetScale API token, potentially compromising database management and operations. | api-token |  |
| planetscale-oauth-token | Found a PlanetScale OAuth token, posing a risk to database access control and sensitive data integrity. | access-token |  |
| postman-api-token | Uncovered a Postman API token, potentially compromising API testing and development workflows. | api-token |  |
| prefect-api-token | Detected a Prefect API token, risking unauthorized access to workflow management and automation services. | api-token |  |
| private-key | Identified a Private Key, which may compromise cryptographic security and sensitive data encryption. | private-key |  |
| pulumi-api-token | Found a Pulumi API token, posing a risk to infrastructure as code services and cloud resource management. | api-token |  |
| pypi-upload-token | Discovered a PyPI upload token, potentially compromising Python package distribution and repository integrity. | upload-token |  |
| rapidapi-access-token | Uncovered a RapidAPI Access Token, which could lead to unauthorized access to various APIs and data services. | access-token |  |
| readme-api-token | Detected a Readme API token, risking unauthorized documentation management and content exposure. | api-token |  |
| rubygems-api-token | Identified a Rubygem API token, potentially compromising Ruby library distribution and package management. | api-token |  |
| sendbird-access-id | Discovered a Sendbird Access ID, which could compromise chat and messaging platform integrations. | access-id |  |
| sendbird-access-token | Uncovered a Sendbird Access Token, potentially risking unauthorized access to communication services and user data. | access-token |  |
| sendgrid-api-token | Detected a SendGrid API token, posing a risk of unauthorized email service operations and data exposure. | api-token |  |
| sendinblue-api-token | Identified a Sendinblue API token, which may compromise email marketing services and subscriber data privacy. | api-token |  |
| sentry-access-token | Found a Sentry Access Token, risking unauthorized access to error tracking services and sensitive application data. | access-token |  |
| shippo-api-token | Discovered a Shippo API token, potentially compromising shipping services and customer order data. | api-token |  |
| shopify-access-token | Uncovered a Shopify access token, which could lead to unauthorized e-commerce platform access and data breaches. | access-token |  |
| shopify-custom-access-token | Detected a Shopify custom access token, potentially compromising custom app integrations and e-commerce data security. | access-token |  |
| shopify-private-app-access-token | Identified a Shopify private app access token, risking unauthorized access to private app data and store operations. | access-token |  |
| shopify-shared-secret | Found a Shopify shared secret, posing a risk to application authentication and e-commerce platform security. | public-secret |  |
| sidekiq-secret | Discovered a Sidekiq Secret, which could lead to compromised background job processing and application data breaches. | secret-key |  |
| sidekiq-sensitive-url | Uncovered a Sidekiq Sensitive URL, potentially exposing internal job queues and sensitive operation details. | sensitive-url |  |
| slack-bot-token | Identified a Slack Bot token, which may compromise bot integrations and communication channel security. | access-token |  |
| slack-app-token | Detected a Slack App-level token, risking unauthorized access to Slack applications and workspace data. | access-token |  |
| slack-legacy-token | Detected a Slack Legacy token, risking unauthorized access to older Slack integrations and user data. | access-token |  |
| slack-user-token | Found a Slack User token, posing a risk of unauthorized user impersonation and data access within Slack workspaces. | access-token |  |
| slack-config-access-token | Found a Slack Configuration access token, posing a risk to workspace configuration and sensitive data access. | access-token |  |
| slack-config-refresh-token | Discovered a Slack Configuration refresh token, potentially allowing prolonged unauthorized access to configuration settings. | refresh-token |  |
| slack-legacy-bot-token | Uncovered a Slack Legacy bot token, which could lead to compromised legacy bot operations and data exposure. | access-token |  |
| slack-legacy-workspace-token | Identified a Slack Legacy Workspace token, potentially compromising access to workspace data and legacy features. | access-token |  |
| slack-webhook-url | Discovered a Slack Webhook, which could lead to unauthorized message posting and data leakage in Slack channels. | webhook |  |
| stripe-access-token | Found a Stripe Access Token, posing a risk to payment processing services and sensitive financial data. | access-token |  |
| square-access-token | Detected a Square Access Token, risking unauthorized payment processing and financial transaction exposure. | access-token |  |
| squarespace-access-token | Identified a Squarespace Access Token, which may compromise website management and content control on Squarespace. | access-token |  |
| sumologic-access-token | Uncovered a SumoLogic Access Token, which could lead to unauthorized access to log data and analytics insights. | access-token |  |
| snyk-api-token | Uncovered a Snyk API token, potentially compromising software vulnerability scanning and code security. | api-key |  |
| microsoft-teams-webhook | Uncovered a Microsoft Teams Webhook, which could lead to unauthorized access to team collaboration tools and data leaks. | webhook |  |
| telegram-bot-api-token | Detected a Telegram Bot API Token, risking unauthorized bot operations and message interception on Telegram. | api-token |  |
| travisci-access-token | Identified a Travis CI Access Token, potentially compromising continuous integration services and codebase security. | access-token |  |
| twilio-api-key | Found a Twilio API Key, posing a risk to communication services and sensitive customer interaction data. | api-key |  |
| twitch-api-token | Discovered a Twitch API token, which could compromise streaming services and account integrations. | api-token |  |
| twitter-api-key | Identified a Twitter API Key, which may compromise Twitter application integrations and user data security. | api-key |  |
| twitter-api-secret | Found a Twitter API Secret, risking the security of Twitter app integrations and sensitive data access. | api-key |  |
| twitter-access-token | Detected a Twitter Access Token, posing a risk of unauthorized account operations and social media data exposure. | access-token |  |
| twitter-access-secret | Uncovered a Twitter Access Secret, potentially risking unauthorized Twitter integrations and data breaches. | public-secret |  |
| twitter-bearer-token | Discovered a Twitter Bearer Token, potentially compromising API access and data retrieval from Twitter. | api-token |  |
| typeform-api-token | Uncovered a Typeform API token, which could lead to unauthorized survey management and data collection. | api-token |  |
| vault-batch-token | Detected a Vault Batch Token, risking unauthorized access to secret management services and sensitive data. | api-token |  |
| vault-service-token | Identified a Vault Service Token, potentially compromising infrastructure security and access to sensitive credentials. | api-token |  |
| yandex-api-key | Discovered a Yandex API Key, which could lead to unauthorized access to Yandex services and data manipulation. | api-key |  |
| yandex-aws-access-token | Uncovered a Yandex AWS Access Token, potentially compromising cloud resource access and data security on Yandex Cloud. | access-token |  |
| yandex-access-token | Found a Yandex Access Token, posing a risk to Yandex service integrations and user data privacy. | access-token |  |
| zendesk-secret-key | Detected a Zendesk Secret Key, risking unauthorized access to customer support services and sensitive ticketing data. | secret-key |  |
| authenticated-url | Identify username:password inside URLS | sensitive-url |  |
<!-- table:end -->
