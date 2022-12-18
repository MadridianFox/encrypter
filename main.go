package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/spf13/cobra"
	"log"
	"os"
	"regexp"
	"strings"
)

var (
	keyPath    string
	filePath   string
	outputPath string
)

func main() {
	err := createCliCommandsTree().Execute()
	if err != nil {
		fmt.Println(err)
	}
}

func createCliCommandsTree() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "encrypter",
		Short: "Инструмент для частичного шифрования файлов конфигурации",
	}

	encryptCmd := &cobra.Command{
		Use:   "encrypt",
		Short: "Зашифровать одно значение",
		Long:  "Принимает значенине и возвращает строку, которую можно ставить в текстовый файл.",
		Run: func(cmd *cobra.Command, args []string) {
			err := encrypt(keyPath, filePath, outputPath)
			if err != nil {
				log.Fatal(err)
			}
		},
	}
	encryptCmd.Flags().StringVarP(&keyPath, "key", "k", "", "путь до публичного ключа")
	encryptCmd.Flags().StringVarP(&filePath, "in", "i", "-", "путь до входного файла (используйте '-' для чтения из stdin)")
	encryptCmd.Flags().StringVarP(&outputPath, "out", "o", "-", "путь до выходного файла (используйте '-' для записи в stdout)")

	rootCmd.AddCommand(encryptCmd)

	decryptCmd := &cobra.Command{
		Use:   "decrypt",
		Short: "Расшифровать текстовый файл",
		Long:  "Найти все зашифрованные участки в текстовом файле и заменить из расшифрованным содержимым.",
		Run: func(cmd *cobra.Command, args []string) {
			err := decrypt(keyPath, filePath, outputPath)
			if err != nil {
				log.Fatal(err)
			}
		},
	}
	decryptCmd.Flags().StringVarP(&keyPath, "key", "k", "", "путь до приватного ключа")
	decryptCmd.Flags().StringVarP(&filePath, "in", "i", "-", "путь до входного файла (используйте '-' для чтения из stdin)")
	decryptCmd.Flags().StringVarP(&outputPath, "out", "o", "-", "путь до выходного файла (используйте '-' для записи в stdout)")

	rootCmd.AddCommand(decryptCmd)

	keygenCmd := &cobra.Command{
		Use:   "keygen [KEY]",
		Short: "Сгенерировать ключи шифрования",
		Long:  "Создать пару ключей RSA 2048 bit. Необходимо указать путь до файла без расширения.",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			err := createKeyPair(args[0])
			if err != nil {
				log.Fatal(err)
			}
		},
	}

	rootCmd.AddCommand(keygenCmd)

	return rootCmd
}

func encrypt(publicKeyPath string, filePath string, outFilePath string) error {
	keyData, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return err
	}

	if filePath == "-" {
		filePath = "/dev/stdin"
	}

	fileData, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	fileData = bytes.TrimSpace(fileData)

	block, _ := pem.Decode(keyData)
	if block == nil {
		return errors.New("key is not a PEM file")
	}

	if block.Type != "PUBLIC KEY" {
		return errors.New("key is not a rsa public key")
	}

	key, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return err
	}

	encryptedData, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, key, fileData, nil)
	if err != nil {
		return err
	}

	b64encodedData := base64.StdEncoding.EncodeToString(encryptedData)
	resultString := fmt.Sprintf("encrypted:%s\n", b64encodedData)

	if outFilePath == "-" {
		outFilePath = "/dev/stdout"
	}

	err = os.WriteFile(outFilePath, []byte(resultString), 0)
	if err != nil {
		return err
	}

	return nil
}

func readPrivateKey(privateKeyPath string) (*rsa.PrivateKey, error) {
	keyData, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, errors.New("key is not a PEM file")
	}

	if block.Type != "PRIVATE KEY" {
		return nil, errors.New("key is not a rsa private key")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func decrypt(privateKeyPath string, filePath string, outFilePath string) error {
	if filePath == "-" {
		filePath = "/dev/stdin"
	}

	fileData, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	key, err := readPrivateKey(privateKeyPath)
	if err != nil {
		return err
	}

	pattern := regexp.MustCompile(`encrypted:[a-zA-Z0-9+/=]+`)
	resultString := pattern.ReplaceAllFunc(fileData, func(item []byte) []byte {
		b64decoded := strings.Replace(string(item), "encrypted:", "", 1)
		data, err := base64.StdEncoding.DecodeString(b64decoded)
		if err != nil {
			log.Println(err)
			return item
		}

		resultString, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, data, nil)
		if err != nil {
			log.Println(err)
			return item
		}

		return resultString
	})

	if outFilePath == "-" {
		outFilePath = "/dev/stdout"
	}

	err = os.WriteFile(outFilePath, []byte(resultString), 0)
	if err != nil {
		return err
	}

	return nil
}

func createKeyPair(keyPath string) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	privateKeyPath := fmt.Sprintf("%s.pem", keyPath)
	err = savePrivateKey(privateKeyPath, privateKey)
	if err != nil {
		return err
	}

	publicKeyPath := fmt.Sprintf("%s.pub.pem", keyPath)
	err = savePublicKey(publicKeyPath, privateKey)
	if err != nil {
		return err
	}

	return nil
}

func savePrivateKey(privateKeyPath string, privateKey *rsa.PrivateKey) error {
	privateKeyBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	file, err := os.Create(privateKeyPath)
	if err != nil {
		return err
	}

	err = pem.Encode(file, privateKeyBlock)

	return err
}

func savePublicKey(publicKeyFile string, privateKey *rsa.PrivateKey) error {
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&privateKey.PublicKey),
	}

	file, err := os.Create(publicKeyFile)
	if err != nil {
		return err
	}

	err = pem.Encode(file, publicKeyBlock)

	return err
}
