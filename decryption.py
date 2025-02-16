import base64
import json
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

# Chave derivada de "FJUC34"
key = SHA256.new("FJUC34".encode()).digest()

# Caminho para o arquivo encriptado
file_path = "C:/Users/MMessa/Documents/Marketing/descriptografador/crypt.txt"

with open(file_path, "r") as file:
    encrypted_funnel = file.read().strip()

# Dividindo IV e o texto cifrado
try:
    iv_base64, cipher_text_base64 = encrypted_funnel.split(":")
    iv = base64.b64decode(iv_base64)
    cipher_text = base64.b64decode(cipher_text_base64)

    # Descriptografando usando AES-256-CBC
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_bytes = cipher.decrypt(cipher_text)

    # Removendo padding
    pad_len = decrypted_bytes[-1]
    decrypted_data = decrypted_bytes[:-pad_len].decode("utf-8")

    # Analisando dados JSON
    decrypted_json = json.loads(decrypted_data)

    # **Escrevendo os dados descriptografados em um novo arquivo**
    output_file_path = "C:/Users/MMessa/Documents/Marketing/descriptografador/decrypt.txt"
    with open(output_file_path, "w", encoding="utf-8") as output_file:
        # Se quiser salvar como texto simples:
        output_file.write(decrypted_data)
        # Ou, se preferir salvar como JSON formatado:
        # json.dump(decrypted_json, output_file, ensure_ascii=False, indent=4)

    print("Descriptografia concluída com sucesso! Dados salvos em:", output_file_path)

except Exception as e:
    print(f"Ocorreu um erro durante a descriptografia: {e}")
