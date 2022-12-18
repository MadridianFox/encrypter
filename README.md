# Encrypted

Простая обёртка над openssl для хранения секретов в git репозитории.

## Usage

Генерируем ключи шифрования.
```bash
encrypter keygen /path/to/keys/my-key
```
В результате будет создано два ключа: my-key.pem и my-key.pub.pem.
Это обычные RSA keypair, 2048 бит.

Допустим мы хотим хранить пароль от БД в конфиге.
Зашифруем пароль
```bash
echo 123456 | encrypter encrypt -key /path/to/keys/my-key.pub.pem
```
В ответ вы получите строку вида
```
encrypted:Fj2WZZpkAkqtzzXK6NQhsJyvnCOWY9cNb8MglrFEuAf1H/mRDYbq1id6+zSYIhYG7t9OfVoVzbTfT0Zuhfz3As6WqI0ZkZn4sNf3Cl/L+x8IaGKVc9mA0Mfqjd9VlMHoxXSym8A6dFFsB1hw1TpwUmyLixmQpsib2FQNW8sOfEQFWa2jjU5pY344OBmDCcEkiFFbL4xgEcDx56csAP8YaDnslxVtII1yYu7H1Y4HmkmuzNg0mZMyNKlg4CoTwHUg4eH1xWdRvtFt8ouN/n6OtLkRghDBlkT7UlT5RS1y8ZuMULplHlCHmj9RLtV3wqh/9Hmh5UTECBjy3CGThGN3tQ==
```
Её можно вставить в любой текстовый файл в то место, где в итоге должен быть расшифрованный секрет, например:
```yaml
system:
  database:
    login: admin
    password: encrypted:mvHAAwaFb2PIRj9i+h5zIZMzkWtNvz/3jdioFwMsaseNIwMihkU6CYxteIqCtfAftLRqfFt3ql6I2IVmHPbaMlsLjmshOobD/4qUyhd0FWBq4QDKPQp4bGNwYuGJChzAJUIqfyOGXP3RguK58HdsC3BQphZjHkK01pUN9fLCmH6aOFiyu/EeB54HZfNZ/EBjGr6W85ONehhm0zWQusMSnFkSRksTiFJxxEqktA1xJvF+SYGInFtZjLQlZSH2ZJ9P8EiY+sY9bnSkNi11pmGMsX5TFS8UeMkNCRCXDDHkhjQ/pUkp9NXalEm1AfyDCOBTxDndaLE3Y7un9wupyCOMdg==
```

Далее, когда хотим получить расшифрованный, готовый к использованию конфиг, обрабатываем его с помощью приватного ключа.
```bash
encrypter decrypt -key /path/to/keys/my-key.pub.pem -in my-encrypted-config.yaml -out my-config.yaml
```
В результате получим расшифрованный файл
```yaml
system:
  database:
    login: admin
    password: 123456
```