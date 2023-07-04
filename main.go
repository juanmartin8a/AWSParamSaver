package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

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

	var isParameterAFile bool

	var name string
	var plainText string
	var keyID string

	fmt.Print("Parameter Name: ")
	fmt.Scan(&name)

	for {
		var response string

		fmt.Print("Is Parameter a JSON file? (y/n): ")
		fmt.Scanln(&response)

		response = strings.ToLower(strings.TrimSpace(response))

		if response == "y" || response == "yes" {
			isParameterAFile = true
			break
		} else if response == "n" || response == "no" {
			isParameterAFile = false
			break
		} else {
			fmt.Println("Invalid input, please type 'y' or 'n'.")
		}
	}

	if isParameterAFile {
		fmt.Print("JSON File Path: ")
		fmt.Scan(&plainText)
	} else {
		fmt.Print("Parameter Value: ")
		fmt.Scan(&plainText)
	}

	fmt.Print("Encryption Key ID: ")
	fmt.Scan(&keyID)

	var plainTextValue []byte

	if isParameterAFile {
		fileBytes, err := ioutil.ReadFile(plainText)
		if err != nil {
			log.Fatalf("Error reading file: %v", err)
		}

		var jsonData map[string]interface{}
		err = json.Unmarshal(fileBytes, &jsonData)
		if err != nil {
			log.Fatalf("Error parsing JSON: %v", err)
		}

		jsonBytes, err := json.Marshal(jsonData)
		if err != nil {
			log.Fatalf("Error encoding JSON: %v", err)
		}

		plainTextValue = jsonBytes

	} else {
		plainTextValue = []byte(plainText)
	}

	encryptedKeyOutput, err := kmsClient.Encrypt(context.TODO(), &kms.EncryptInput{
		KeyId:     &keyID,
		Plaintext: plainTextValue,
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
