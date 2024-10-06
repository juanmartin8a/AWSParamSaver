# AWSParamSaver
This CLI wizard can be used to store strings in AWS Parameter Store. AWS KMS keys can be used to encrypt the messages :)

## Why
I made this wizard out of convenience since I use AWS parameter store a lot to store for the most part API keys securely. Most importantly the CLI commands were annoying and seemed like too much work.

## Usage
1. ### Clone the project
    `git clone https://github.com/juanmartin8a/AWSParamSaver.git`

2. ### Start the wizard
    `go run main`

    If you want to use aws-vault:

    `aws-vault exec <profile> -- go run .`

3. ### Follow along ;)
