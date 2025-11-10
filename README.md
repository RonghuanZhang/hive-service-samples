# Encryption/Decryption API Documentation

## Encryption API
- Endpoint: `POST /encrypt`
- Request Parameters (JSON):
  - `plaintext`: The plain text string to be encrypted
  - `key`: The encryption key (must be 16, 24, or 32 bytes in length)
- Response Parameters (JSON):
  - `ciphertext`: The encrypted text (Base64 encoded)

### Example curl command
```sh
curl -X POST http://localhost:8080/encrypt \
  -H "Content-Type: application/json" \
  -d '{"plaintext":"hello world","key":"1234567890abcdef"}'
```

## Decryption API
- Endpoint: `POST /decrypt`
- Request Parameters (JSON):
  - `ciphertext`: The encrypted text (Base64 encoded)
  - `key`: The decryption key (must be 16, 24, or 32 bytes, same as used for encryption)
- Response Parameters (JSON):
  - `plaintext`: The decrypted plain text string

### Example curl command
```sh
curl -X POST http://localhost:8080/decrypt \
  -H "Content-Type: application/json" \
  -d '{"ciphertext":"ENCRYPTED_TEXT","key":"1234567890abcdef"}'
```

> Replace `ENCRYPTED_TEXT` with the actual ciphertext returned from the encryption API.

## Weather API
- Endpoint: `GET /weather`
- Request Parameters (Query):
  - `latitude`: Latitude of the location (required)
  - `longitude`: Longitude of the location (required)
- Response Parameters (JSON):
  - Returns weather data from Open-Meteo API, including:
    - `current`: Current temperature (`current`)
    - `hourly`: Hourly temperature (`hourly`)

### Example curl command
```sh
curl -X GET "http://localhost:8080/weather?latitude=52.52&longitude=13.41"
```
