package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

func main() {
	region := os.Getenv("AWS_REGION")
	accessKeyID := os.Getenv("AWS_ACCESS_KEY_ID")
	secretAccessKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	sessionToken := os.Getenv("AWS_SESSION_TOKEN")

	if region == "" || accessKeyID == "" || secretAccessKey == "" || sessionToken == "" {
		fmt.Print("AWS Region: ")
		fmt.Scan(&region)

		fmt.Print("AWS access key ID: ")
		fmt.Scan(&accessKeyID)

		fmt.Print("AWS secret access key: ")
		fmt.Scan(&secretAccessKey)

		fmt.Print("AWS session token: ")
		fmt.Scan(&sessionToken)
	}

	creds := credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, sessionToken)
	cfg, err := config.LoadDefaultConfig(
		context.TODO(),
		config.WithRegion(region),
		config.WithCredentialsProvider(creds),
	)
	if err != nil {
		log.Fatalf("Unable to load AWS config: %v", err)
	}

	svc := ssm.NewFromConfig(cfg)
	kmsClient := kms.NewFromConfig(cfg)

	var name string
	var plainText string
	var keyID string

	fmt.Print("Parameter Name: ")
	fmt.Scan(&name)

	fmt.Print("Parameter Value: ")
	fmt.Scan(&plainText)

	fmt.Print("Encryption Key ID: ")
	fmt.Scan(&keyID)

	encryptedKeyOutput, err := kmsClient.Encrypt(context.TODO(), &kms.EncryptInput{
		KeyId:     &keyID,
		Plaintext: []byte(plainText),
	})
	if err != nil {
		log.Fatalf("Error encrypting plaintext: %v", err)
	}

	encodedKey := base64.StdEncoding.EncodeToString(encryptedKeyOutput.CiphertextBlob)

	log.Printf("Encrypted and encoded value: %s", encodedKey)

	input := &ssm.PutParameterInput{
		Name:      aws.String(name),
		Value:     &encodedKey,
		Type:      types.ParameterTypeSecureString,
		KeyId:     &keyID,
		Overwrite: aws.Bool(true),
	}

	_, err = svc.PutParameter(context.TODO(), input)
	if err != nil {
		log.Fatalf("Error putting parameter value: %v", err)
	}

	output, _ := svc.GetParameter(context.TODO(), &ssm.GetParameterInput{
		Name:           aws.String(name),
		WithDecryption: aws.Bool(true),
	})

	log.Printf("Stored Value: %s", *output.Parameter.Value)

	decoded, err := base64.StdEncoding.DecodeString(*output.Parameter.Value)
	if err != nil {
		log.Fatalf("Error decoding parameter value: %v", err)
	}

	decryptedOutput, err := kmsClient.Decrypt(context.TODO(), &kms.DecryptInput{
		CiphertextBlob: decoded,
	})
	if err != nil {
		log.Fatalf("Error decrypting parameter value: %v", err)
	}

	log.Printf("Stored value after being decrypted and decoded: %s", string(decryptedOutput.Plaintext))
}
