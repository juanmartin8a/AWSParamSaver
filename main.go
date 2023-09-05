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

    var choice int

	for {
		fmt.Println("What do you want to do?:")
		fmt.Println("1: Add new parameter")
		fmt.Println("2: Get parameter")

		fmt.Scanln(&choice)

        if choice != 1 && choice != 2 {
            log.Printf("Invalid Choice")
        }

        if choice == 1 {
            createParameter(svc, kmsClient)
        } else if choice == 2 {
            getParameter(svc, kmsClient)
        }
	}
}

func createParameter(svc *ssm.Client, kmsClient *kms.Client) {
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
			log.Println("Invalid input, please type 'y' or 'n'.")
		}
	}

	if isParameterAFile {
		fmt.Print("JSON File Path: ")
		fmt.Scan(&plainText)
	} else {
		fmt.Print("Parameter Value: ")
		fmt.Scan(&plainText)
	}

    var isEncrypted bool

	for {
		var response string

		fmt.Print("Encrypt Parameter? (y/n): ")
		fmt.Scanln(&response)

		response = strings.ToLower(strings.TrimSpace(response))

		if response == "y" || response == "yes" {
			isEncrypted = true
			break
		} else if response == "n" || response == "no" {
			isEncrypted = false
			break
		} else {
			fmt.Println("Invalid input, please type 'y' or 'n'.")
		}
	}

    if isEncrypted {
        fmt.Print("Encryption Key ID: ")
        fmt.Scan(&keyID)
    }

	var plainTextValue []byte

	if isParameterAFile {
		fileBytes, err := os.ReadFile(plainText)
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

    value := string(plainTextValue)

    if isEncrypted {
        encryptedKeyOutput, err := kmsClient.Encrypt(context.TODO(), &kms.EncryptInput{
            KeyId:     &keyID,
            Plaintext: plainTextValue,
        })
        if err != nil {
            log.Fatalf("Error encrypting plaintext: %v", err)
        }

        encodedKey := base64.StdEncoding.EncodeToString(encryptedKeyOutput.CiphertextBlob)

        log.Printf("Encrypted and encoded value: %s", encodedKey)

        value = encodedKey 
    }


	input := &ssm.PutParameterInput{
		Name:      aws.String(name),
		Value:     &value,
		Type:      types.ParameterTypeSecureString,
		KeyId:     &keyID,
		Overwrite: aws.Bool(true),
	}

    _, err := svc.PutParameter(context.TODO(), input)
	if err != nil {
		log.Fatalf("Error putting parameter: %v", err)
	}

    log.Println("Success adding new parameter")
    os.Exit(0)
}

func getParameter(ssmClient *ssm.Client, kmsClient *kms.Client) {
    var name string
    var isEncrypted bool

    fmt.Print("Parameter Name: ")
    fmt.Scan(&name)

	for {
		var response string

		fmt.Print("Is the parameter encrypted? (y/n): ")
		fmt.Scanln(&response)

		response = strings.ToLower(strings.TrimSpace(response))

		if response == "y" || response == "yes" {
			isEncrypted = true
			break
		} else if response == "n" || response == "no" {
			isEncrypted = false
			break
		} else {
			fmt.Println("Invalid input, please type 'y' or 'n'.")
		}
	}


	output, _ := ssmClient.GetParameter(context.TODO(), &ssm.GetParameterInput{
		Name:           aws.String(name),
		WithDecryption: aws.Bool(isEncrypted),
	})

    var value string

    if !isEncrypted {
        value = *output.Parameter.Value
        log.Printf("Stored Value: %s", value)
        os.Exit(0)
    }

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

    log.Printf("Decrypted Stored Value: %s", string(decryptedOutput.Plaintext))
    os.Exit(0)
 }

// TO DO
// func deleteParameter() {
// }
