import base64
import json
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

# Chave derivada de "FJUC34"
key = SHA256.new("FJUC34".encode()).digest()

# Caminho para o arquivo com os dados a serem criptografados
input_file_path = r"C:/Users/MMessa/Documents/Marketing/site/pythonDescript/descriptografado.txt"

# Ler os dados que serão criptografados
with open(input_file_path, "r", encoding="utf-8") as file:
    # Se o arquivo contém JSON formatado
    # data_to_encrypt = json.load(file)
    # data_str = json.dumps(data_to_encrypt, ensure_ascii=False)

    # Se o arquivo contém texto simples
    data_str = file.read()

# Converter a string em bytes
data_bytes = data_str.encode('utf-8')

# Aplicar padding para que o tamanho dos dados seja múltiplo de 16 bytes
padded_data = pad(data_bytes, AES.block_size)

# Gerar um IV aleatório de 16 bytes
iv = get_random_bytes(16)

# Criptografar os dados
cipher = AES.new(key, AES.MODE_CBC, iv)
cipher_text = cipher.encrypt(padded_data)

# Codificar o IV e o texto cifrado em Base64
iv_base64 = base64.b64encode(iv).decode('utf-8')
cipher_text_base64 = base64.b64encode(cipher_text).decode('utf-8')

# Concatenar o IV e o texto cifrado com dois pontos
encrypted_data = f"{iv_base64}:{cipher_text_base64}"

# Salvar o texto cifrado no arquivo desejado
output_file_path = r"C:/Users/MMessa/Documents/Marketing/site/pythonDescript/encrypt.txt"
with open(output_file_path, "w", encoding="utf-8") as file:
    file.write(encrypted_data)

print("Criptografia concluída com sucesso! Dados salvos em:", output_file_path)
