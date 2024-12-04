import re


quote = r"['\"]?"
connect = r"\s*(:|=>|=)?\s*"
end_secret = r"[.,]?(\s+|$)"
start_word = r"([^0-9a-zA-Z]|^)"
aws = r"aws_?"


SECRET_PATTERNS = [
    {
        "name": "AWS Access Key",
        "pattern": re.compile(rf"(?P<secret>(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}){quote}{end_secret}"),
        "description": "aws-access-key-id"
    },
    {
        "name": "AWS Secret Access Key",
        "pattern": re.compile(rf"(?i){quote}{aws}{quote}{connect}{quote}(sec(ret)?)?_?(access)?_?key{quote}{quote}{end_secret}(?P<secret>[A-Za-z0-9\/\+=]{{40}}){end_secret}"),
        "description": "aws-secret-access-key",
    },
    {
        "name": "Github Personal Access Token",
        "pattern": re.compile(rf"(?P<secret>ghp_[0-9a-zA-Z]{36})"),
        "description": "github-pat",
    },
    {
        "name": "GitHub OAuth Access Token",
        "pattern": re.compile(rf"(?P<secret>gho_[0-9a-zA-Z]{36})"),
        "description": "github-oauth",
    },
    {
        "name": "GitHub App Token",
        "pattern": re.compile(rf"(?P<secret>(ghu|ghs)_[0-9a-zA-Z]{36})"),
        "description": "github-app-token",
    },
    {
        "name": "GitHub Refresh Token",
        "pattern": re.compile(rf"(?P<secret>ghr_[0-9a-zA-Z]{76})"),
        "description": "github-refresh-token",
    },
    {
        "name": "GitHub Fine-grained Personal Access Token Token",
        "pattern": re.compile(rf"github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}"),
        "description": "github-fine-grained-pat",
    },
    {
        "name": "Hugging Face Access Token",
        "pattern": re.compile(rf"(?P<secret>hf_[A-Za-z0-9]{34,40})"),
        "description": "github-fine-grained-pat",
    },
    {
        "name": "Asymmetric Private Key",
        "pattern": re.compile(rf"(?i)-----\s*?BEGIN[ A-Z0-9_-]*?PRIVATE KEY( BLOCK)?\s*?-----[\s]*?(?P<secret>[A-Za-z0-9=+/\\\r\n][A-Za-z0-9=+/\\\s]+)[\s]*?-----\s*?END[ A-Z0-9_-]*? PRIVATE KEY( BLOCK)?\s*?-----"),
        "description": "private-key",
    },
    {
        "name": "Shopify Token",
        "pattern": re.compile(rf"shp(ss|at|ca|pa)_[a-fA-F0-9]{32}"),
        "description": "shopify-token",
    },
    {
        "name": "Slack Token",
        "pattern": re.compile(rf"(?P<secret>xox[baprs]-([0-9a-zA-Z]{10,48}))"),
        "description": "slack-access-token",
    },
    {
        "name": "Stripe Publishable Key",
        "pattern": re.compile(rf"(?i)(?P<secret>pk_(test|live)_[0-9a-z]{10,32})"),
        "description": "stripe-publishable-token",
    },
    {
        "name": "Stripe Secret Key",
        "pattern": re.compile(rf"(?i)(?P<secret>sk_(test|live)_[0-9a-z]{10,32})"),
        "description": "stripe-secret-token",
    },
    {
        "name": "PyPI Upload Token",
        "pattern": re.compile(rf"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,1000}"),
        "description": "pypi-upload-token",
    },
    {
        "name": "Google (GCP) Service Account",
        "pattern": re.compile(rf'"type": "service_account"'),
        "description": "gcp-service-account",
    },
    {
        "name": "Heroku API Key",
        "pattern": re.compile(rf"(?i)(?P<key>heroku[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}[\'\"](?P<secret>[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})[\'\"]"),
        "description": "heroku-api-key",
    },
    {
        "name": "Slack Webhook",
        "pattern": re.compile(rf"https:\/\/hooks.slack.com\/services\/[A-Za-z0-9+\/]{44,48}"),
        "description": "slack-web-hook",
    },
    {
        "name": "Twilio API Key",
        "pattern": re.compile(rf"SK[0-9a-fA-F]{32}"),
        "description": "twilio-api-key",
    },
    {
        "name": "Age Secret Key",
        "pattern": re.compile(rf"AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}"),
        "description": "age-secret-key",
    },
    {
        "name": "Facebook Token",
        "pattern": re.compile(rf"(?i)(?P<key>facebook[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-f0-9]{32})['\"]"),
        "description": "facebook-token",
    },
    {
        "name": "Twitter Token",
        "pattern": re.compile(rf"(?i)(?P<key>twitter[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-f0-9]{35,44})['\"]"),
        "description": "twitter-token",
    },
    {
        "name": "Adobe Client ID (OAuth Web)",
        "pattern": re.compile(rf"(?i)(?P<key>adobe[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-f0-9]{32})['\"]"),
        "description": "adobe-client-id",
    },
    {
        "name": "Adobe Client Secret",
        "pattern": re.compile(rf"(?i)(p8e-)[a-z0-9]{32}"),
        "description": "adobe-client-secret",
    },
    {
        "name": "Alibaba AccessKey ID",
        "pattern": re.compile(rf"(?i)([^0-9A-Za-z]|^)(?P<secret>(LTAI)[a-z0-9]{20})([^0-9A-Za-z]|$)"),
        "description": "alibaba-access-key-id",
    },
    {
        "name": "Alibaba Secret Key",
        "pattern": re.compile(rf"(?i)(?P<key>alibaba[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}[\'\"](?P<secret>[a-z0-9]{30})[\'\"]"),
        "description": "alibaba-secret-key",
    },
    {
        "name": "Asana Client ID",
        "pattern": re.compile(rf"(?i)(?P<key>asana[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[0-9]{16})['\"]"),
        "description": "asana-client-id",
    },
    {
        "name": "Asana Client Secret",
        "pattern": re.compile(rf"(?i)(?P<key>asana[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9]{32})['\"]"),
        "description": "asana-client-secret",
    },
    {
        "name": "Atlassian API Token",
        "pattern": re.compile(rf"(?i)(?P<key>atlassian[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9]{24})['\"]"),
        "description": "atlassian-api-token",
    },
    {
        "name": "Bitbucket Client ID",
        "pattern": re.compile(rf"(?i)(?P<key>bitbucket[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9]{32})['\"]"),
        "description": "bitbucket-client-id",
    },
    {
        "name": "Bitbucket Client Secret",
        "pattern": re.compile(rf"(?i)(?P<key>bitbucket[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9_\-]{64})['\"]"),
        "description": "bitbucket-client-secret",
    },
    {
        "name": "Beamer API Token",
        "pattern": re.compile(rf"(?i)(?P<key>beamer[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>b_[a-z0-9=_\-]{44})['\"]"),
        "description": "beamer-api-token",
    },
    {
        "name": "Clojars API Token",
        "pattern": re.compile(rf"(?i)(CLOJARS_)[a-z0-9]{60}"),
        "description": "clojars-api-token",
    },
    {
        "name": "Contentful Delivery API Token",
        "pattern": re.compile(rf"(?i)(?P<key>contentful[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9\-=_]{43})['\"]"),
        "description": "contentful-delivery-api-token",
    },
    {
        "name": "Databricks API Token",
        "pattern": re.compile(rf"dapi[a-h0-9]{32}"),
        "description": "databricks-api-token",
    },
    {
        "name": "Discord API Token",
        "pattern": re.compile(rf"(?i)(?P<key>discord[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-h0-9]{64})['\"]"),
        "description": "discord-api-token",
    },
    {
        "name": "Discord Client ID",
        "pattern": re.compile(rf"(?i)(?P<key>bitbucket[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9]{32})['\"]"),
        "description": "discord-client-id",
    },
    {
        "name": "Discord Client Secret",
        "pattern": re.compile(rf"(?i)(?P<key>discord[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9=_\-]{32})['\"]"),
        "description": "discord-client-secret",
    },
    {
        "name": "Dropbox API Secret",
        "pattern": re.compile(rf"(?i)(dropbox[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([a-z0-9]{15})['\"]"),
        "description": "dropbox-api-secret",
    },
    {
        "name": "Dropbox Short Lived API Token",
        "pattern": re.compile(rf"(?i)(dropbox[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](sl\.[a-z0-9\-=_]{135})['\"]"),
        "description": "dropbox-short-lived-api-token",
    },
    {
        "name": "Dropbox Long Lived API Token",
        "pattern": re.compile(rf"(?i)(dropbox[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"][a-z0-9]{11}(AAAAAAAAAA)[a-z0-9\-_=]{43}['\"]"),
        "description": "dropbox-long-lived-api-token",
    },
    {
        "name": "Duffel API Token",
        "pattern": re.compile(rf"['\"]duffel_(test|live)_[a-z0-9_-]{43}['\"]", re.IGNORECASE),
        "description": "duffel-api-token",
    },
    {
        "name": "Dynatrace API Token",
        "pattern": re.compile(rf"['\"]dt0c01\.[a-z0-9]{24}\.[a-z0-9]{64}['\"]", re.IGNORECASE),
        "description": "dynatrace-api-token",
    },
    {
        "name": "EasyPost API Token",
        "pattern": re.compile(rf"(?i)['\"]EZ[AT]K[a-z0-9]{54}['\"]"),
        "description": "easypost-api-token",
    },
    {
        "name": "Fastly API Token",
        "pattern": re.compile(rf"(?i)(?P<key>fastly[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9\-=_]{32})['\"]"),
        "description": "fastly-api-token",
    },
    {
        "name": "Finicity Client Secret",
        "pattern": re.compile(rf"(?i)(?P<key>finicity[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9]{20})['\"]"),
        "description": "finicity-client-secret",
    },
    {
        "name": "Finicity API Token",
        "pattern": re.compile(rf"(?i)(?P<key>finicity[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-f0-9]{32})['\"]"),
        "description": "finicity-api-token",
    },
    {
        "name": "Flutterwave public key",
        "pattern": re.compile(rf"(?i)(?P<secret>SEC)K_TEST-[a-f0-9]{32}-X"),
        "description": "flutterwave-public-key",
    },
    {
        "name": "Flutterwave encrypted key",
        "pattern": re.compile(rf"(?P<secret>FLWSECK_TEST[a-h0-9]{12})"),
        "description": "flutterwave-encrypted-key",
    },
    {
        "name": "Frame.io API Token",
        "pattern": re.compile(rf"(?i)fio-u-[a-z0-9\-_=]{64}"),
        "description": "frameio-api-token",
    },
    {
        "name": "GoCardless API Token",
        "pattern": re.compile(rf"(?i)['\"]live_[a-z0-9\-_=]{40}['\"]"),
        "description": "gocardless-api-token",
    },
    {
        "name": "Grafana API Token",
        "pattern": re.compile(rf"(?i)['\"]eyJrIjoi[a-z0-9\-_=]{72,92}['\"]"),
        "description": "grafana-api-token",
    },
    {
        "name": "Hashicorp Terraform user/org API Token",
        "pattern": re.compile(rf"(?i)['\"][a-z0-9]{14}\.atlasv1\.[a-z0-9\-_=]{60,70}['\"]"),
        "description": "hashicorp-tf-api-token",
    },
    {
        "name": "Hubspot API Token",
        "pattern": re.compile(rf"(?i)(?P<key>hubspot[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-h0-9]{8}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{12})['\"]"),
        "description": "hubspot-api-token",
    },
    {
        "name": "Intercom API Token",
        "pattern": re.compile(rf"(?i)(?P<key>intercom[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9=_]{60})['\"]"),
        "description": "intercom-api-token",
    },
    {
        "name": "Intercom Client Server",
        "pattern": re.compile(rf"(?i)(?P<key>intercom[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-h0-9]{8}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{12})['\"]"),
        "description": "intercom-client-server",
    },
    {
        "name": "Ionic API Token",
        "pattern": re.compile(rf"(?i)(ionic[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](ion_[a-z0-9]{42})['\"]"),
        "description": "ionic-api-token",
    },
    {
        "name": "JWT Token",
        "pattern": re.compile(rf"ey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9\/\\_-]{17,}\.(?:[a-zA-Z0-9\/\\_-]{10,}={0,2})?"),
        "description": "jwt-token",
    },
    {
        "name": "Linear API Token",
        "pattern": re.compile(rf"(?i)lin_api_[a-z0-9]{40}"),
        "description": "linear-api-token",
    },
    {
        "name": "Linear Client Secret",
        "pattern": re.compile(rf"(?i)(?P<key>linear[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-f0-9]{32})['\"]"),
        "description": "linear-client-secret",
    },
    {
        "name": "Lob API Key",
        "pattern": re.compile(rf"(?i)(?P<key>lob[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>(live|test)_[a-f0-9]{35})['\"]"),
        "description": "lob-api-key",
    },
    {
        "name": "Lob Publishable API Key",
        "pattern": re.compile(rf"(?i)(?P<key>lob[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>(test|live)_pub_[a-f0-9]{31})['\"]"),
        "description": "lob-pub-api-key",
    },
    {
        "name": "Mailchimp API Key",
        "pattern": re.compile(rf"(?i)(?P<key>mailchimp[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-f0-9]{32}-us20)['\"]"),
        "description": "mailchimp-api-key",
    },
    {
        "name": "Mailgun Private API Token",
        "pattern": re.compile(rf"(?i)(?P<key>mailgun[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>(pub)?key-[a-f0-9]{32})['\"]"),
        "description": "mailgun-token",
    },
    {
        "name": "Mailgun Webhook Signing Key",
        "pattern": re.compile(rf"(?i)(?P<key>mailgun[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8})['\"]"),
        "description": "mailgun-signing-key",
    },
    {
        "name": "Mapbox API Token",
        "pattern": re.compile(rf"(?i)(pk\.[a-z0-9]{60}\.[a-z0-9]{22})"),
        "description": "mapbox-api-token",
    },
    {
        "name": "MessageBird API Token",
        "pattern": re.compile(rf"(?i)(?P<key>messagebird[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9]{25})['\"]"),
        "description": "messagebird-api-token",
    },
    {
        "name": "MessageBird Client ID",
        "pattern": re.compile(rF"(?i)(?P<key>messagebird[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-h0-9]{8}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{12})['\"]"),
        "description": "messagebird-api-token",
    },
    {
        "name": "New Relic user API Key",
        "pattern": re.compile(rf"['\"](NRAK-[A-Z0-9]{27})['\"]"),
        "description": "new-relic-user-api-key",
    },
    {
        "name": "New Relic user API ID",
        "pattern": re.compile(rf"(?i)(?P<key>newrelic[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[A-Z0-9]{64})['\"]"),
        "description": "new-relic-user-api-id",
    },
    {
        "name": "New Relic ingest browser API token",
        "pattern": re.compile(rf"['\"](NRJS-[a-f0-9]{19})['\"]"),
        "description": "new-relic-browser-api-token",
    },
    {
        "name": "npm access token",
        "pattern": re.compile(rf"(?i)['\"](npm_[a-z0-9]{36})['\"]"),
        "description": "npm-access-token",
    },
    {
        "name": "PlanetScale Password",
        "pattern": re.compile(rf"(?i)pscale_pw_[a-z0-9\-_\.]{43}"),
        "description": "planetscale-password",
    },
    {
        "name": "PlanetScale API token",
        "pattern": re.compile(rf"(?i)pscale_tkn_[a-z0-9\-_\.]{43}"),
        "description": "planetscale-api-token",
    },
    {
        "name": "Postman API token",
        "pattern": re.compile(rf"(?i)PMAK-[a-f0-9]{24}\-[a-f0-9]{34}"),
        "description": "postman-api-token",
    },
    {
        "name": "Pulumi API token",
        "pattern": re.compile(rf"pul-[a-f0-9]{40}"),
        "description": "pulumi-api-token",
    },
    {
        "name": "Rubygems API token",
        "pattern": re.compile(rf"rubygems_[a-f0-9]{48}"rf"pul-[a-f0-9]{40}"),
        "description": "rubygems-api-token",
    },
    {
        "name": "SendGrid API token",
        "pattern": re.compile(rf"(?i)SG\.[a-z0-9_\-\.]{66}"),
        "description": "sendgrid-api-token",
    },
    {
        "name": "Sendinblue API token",
        "pattern": re.compile(rf"(?i)xkeysib-[a-f0-9]{64}\-[a-z0-9]{16}"),
        "description": "sendinblue-api-token",
    },
    {
        "name": "Shippo API token",
        "pattern": re.compile(rf"shippo_(live|test)_[a-f0-9]{40}"),
        "description": "shippo-api-token",
    },
    {
        "name": "Linkedin Client Secret",
        "pattern": re.compile(rf"(?i)(?P<key>linkedin[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z]{16})['\"]"),
        "description": "linkedin-client-secret",
    },
    {
        "name": "Linkedin Client ID",
        "pattern": re.compile(rf"(?i)(?P<key>linkedin[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9]{14})['\"]"),
        "description": "linkedin-client-id",
    },
    {
        "name": "Twitch API Token",
        "pattern": re.compile(rf"(?i)(?P<key>twitch[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"](?P<secret>[a-z0-9]{30})['\"]"),
        "description": "twitch-api-token",
    },
    {
        "name": "Typeform API Token",
        "pattern": re.compile(rf"(?i)(?P<key>typeform[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}(?P<secret>tfp_[a-z0-9\-_\.=]{59})"),
        "description": "typeform-api-token",
    },
    {
        "name": "Dockerconfig Secret",
        "pattern": re.compile(rf"(?i)(\.(dockerconfigjson|dockercfg):\s*\|*\s*(?P<secret>(ey|ew)+[A-Za-z0-9\/\+=]+))"),
        "description": "dockerconfig-secret",
    },
]