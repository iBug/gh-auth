# GH-Auth

An AWS Lambda function to validate the relationship between student IDs and GitHub accounts, using [Yale CAS](https://developers.yale.edu/cas-central-authentication-service) and [GitHub OAuth](https://docs.github.com/en/developers/apps/building-oauth-apps/authorizing-oauth-apps).

## Installation

This app depends only on Ruby's standard libraries so you don't need to install any gem in Lambda environment.

First, ensure you have a working AWS deployment environment. You should [configure any credentials](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html) and/or environment variables so that `aws lambda update-function-code` can be run from the CLI directly. You should set a default region as well.

Next, create a new GitHub OAuth app at <https://github.com/settings/applications/new>. Copy [`config.example.yml`](config.example.yml) to `config.yml` and edit any values accordingly. The config file supports ERB syntax so you can put sensitive information in Lambda environment.

Install deployment tools using `bundle install` and export your function name to `AWS_FUNCTION_NAME` environment variable. Now you can run `bundle exec rake deploy` to deploy the app onto AWS Lambda.

## Notes

This app uses no database and its security relies on the secrecy of `config.yml`. If `config.yml`, or the secret keys in particular, are leaked, your GitHub OAuth app may be compromised and user can craft forged tokens.

## License

[The MIT License](LICENSE)
