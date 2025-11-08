package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/gin-gonic/gin"
)

type EncryptRequest struct {
	PlainText string `json:"plaintext"`
	Key       string `json:"key"`
}

type DecryptRequest struct {
	CipherText string `json:"ciphertext"`
	Key        string `json:"key"`
}

func pkcs7Padding(data []byte, blockSize int) []byte {
	padLen := blockSize - len(data)%blockSize
	pad := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, pad...)
}

func pkcs7UnPadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, fmt.Errorf("invalid padding size")
	}
	padLen := int(data[length-1])
	if padLen > length {
		return nil, fmt.Errorf("invalid padding size")
	}
	return data[:(length - padLen)], nil
}

func aesEncrypt(plainText, key string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	plainBytes := pkcs7Padding([]byte(plainText), block.BlockSize())
	iv := make([]byte, block.BlockSize())
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	cipherBytes := make([]byte, len(plainBytes))
	mode.CryptBlocks(cipherBytes, plainBytes)
	result := append(iv, cipherBytes...)
	return base64.StdEncoding.EncodeToString(result), nil
}

func aesDecrypt(cipherText, key string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	if len(data) < block.BlockSize() {
		return "", fmt.Errorf("ciphertext too short")
	}
	iv := data[:block.BlockSize()]
	cipherBytes := data[block.BlockSize():]
	if len(cipherBytes)%block.BlockSize() != 0 {
		return "", fmt.Errorf("ciphertext is not a multiple of the block size")
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	plainBytes := make([]byte, len(cipherBytes))
	mode.CryptBlocks(plainBytes, cipherBytes)
	plainBytes, err = pkcs7UnPadding(plainBytes)
	if err != nil {
		return "", err
	}
	return string(plainBytes), nil
}

func main() {
	r := gin.Default()

	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	r.GET("/host", func(c *gin.Context) {
		hostname, err := os.Hostname()
		if err != nil {
			c.JSON(500, gin.H{"error": "failed to get hostname"})
			return
		}
		c.JSON(200, gin.H{"host": hostname})
	})

	r.POST("/encrypt", func(c *gin.Context) {
		var req EncryptRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": "invalid request"})
			return
		}
		if len(req.Key) != 16 && len(req.Key) != 24 && len(req.Key) != 32 {
			c.JSON(400, gin.H{"error": "key length must be 16, 24, or 32 bytes"})
			return
		}
		cipherText, err := aesEncrypt(req.PlainText, req.Key)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		c.JSON(200, gin.H{"ciphertext": cipherText})
	})

	r.POST("/decrypt", func(c *gin.Context) {
		var req DecryptRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": "invalid request"})
			return
		}
		if len(req.Key) != 16 && len(req.Key) != 24 && len(req.Key) != 32 {
			c.JSON(400, gin.H{"error": "key length must be 16, 24, or 32 bytes"})
			return
		}
		plainText, err := aesDecrypt(req.CipherText, req.Key)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		c.JSON(200, gin.H{"plaintext": plainText})
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	err := r.Run(":" + port)
	if err != nil {
		return
	}
}
