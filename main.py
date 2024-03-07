import os
import re
import shutil
import sys
import subprocess
import requests
import base64
import random
import string

api_base = ""
RED = '\033[0;31m'
ORANGE = '\033[0;33m'
GREEN = '\033[0;32m'
NC = '\033[0m'


def wireguard_add_user():
    print("Client configuration")
    print("The client name must consist of alphanumeric character(s). It may also include underscores or dashes and can't exceed 15 chars.")
    client_name = input("Client name: ")

    # Generate key pair for the client
    client_priv_key = subprocess.run(["wg", "genkey"], capture_output=True, text=True).stdout.strip()
    client_pub_key = subprocess.run(["wg", "pubkey"], input=client_priv_key, capture_output=True, text=True).stdout.strip()
    client_pre_shared_key = subprocess.run(["wg", "genpsk"], capture_output=True, text=True).stdout.strip()

    # Get server parameters
    server_params_file = "/etc/wireguard/params"
    with open(server_params_file) as f:
        server_params = dict(line.strip().partition('=')[::2] for line in f)

    server_pub_ip = server_params.get("SERVER_PUB_IP", "")
    server_port = server_params.get("SERVER_PORT", "")
    server_wg_nic = server_params.get("SERVER_WG_NIC", "")
    server_pub_key = server_params.get("SERVER_PUB_KEY", "")
    allowed_ips = server_params.get("ALLOWED_IPS", "")

    # Create client file and add the server as a peer
    client_conf = f"""
[Interface]
PrivateKey = {client_priv_key}
Address = {allowed_ips}
DNS = {server_params.get("CLIENT_DNS_1", "")}, {server_params.get("CLIENT_DNS_2", "")}

[Peer]
PublicKey = {server_pub_key}
PresharedKey = {client_pre_shared_key}
Endpoint = {server_pub_ip}:{server_port}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""
    # Сохранение конфигурационного файла клиента
    client_conf_file = f"/root/{server_wg_nic}-client-{client_name}.conf"
    with open(client_conf_file, "w") as f:
        f.write(client_conf)

    # Добавление клиента в качестве пира к серверу
    with open(f"/etc/wireguard/{server_wg_nic}.conf", "a") as f:
        f.write(f"\n### Client {client_name}\n")
        f.write(f"[Peer]\n")
        f.write(f"PublicKey = {client_pub_key}\n")
        f.write(f"PresharedKey = {client_pre_shared_key}\n")
        f.write(f"AllowedIPs = {allowed_ips}\n")
        f.write(f"PersistentKeepalive = 25\n")

    # Считывание параметров из файла WireGuard
    with open("/etc/wireguard/params", "rb") as params_file:
        params_data = params_file.read()

    # Синхронизация конфигурации с помощью утилиты wg
    subprocess.run(["wg", "syncconf", server_wg_nic], input=params_data, text=True)

    # Generate QR code if qrencode is installed
    if shutil.which("qrencode"):
        print(f"\nHere is your client config file as a QR Code:\n")
        subprocess.run(["qrencode", "-t", "ansiutf8", "-l", "L"], input=client_conf.encode(), text=True)
        print("\n")

    print(f"Your client config file is in {client_conf_file}")
    print(client_conf)


def wireguard_list_all_users():
    server_wg_nic = ""
    server_params_file = "/etc/wireguard/params"
    with open(server_params_file) as f:
        for line in f:
            if line.startswith("SERVER_WG_NIC"):
                server_wg_nic = line.strip().split("=")[1]
                break

    client_pattern = re.compile(r"^### Client (.+)$")
    with open(f"/etc/wireguard/{server_wg_nic}.conf") as f:
        clients = [client_pattern.match(line).group(1) for line in f if client_pattern.match(line)]

    if clients:
        print("Existing clients:")
        for i, client in enumerate(clients, 1):
            print(f"{i}) {client}")
    else:
        print("You have no existing clients!")


def wireguard_delete_user():
    wireguard_list_all_users()
    client_number = int(input("Select the existing client you want to revoke: "))
    server_wg_nic = ""
    server_params_file = "/etc/wireguard/params"
    with open(server_params_file) as f:
        for line in f:
            if line.startswith("SERVER_WG_NIC"):
                server_wg_nic = line.strip().split("=")[1]
                break

    client_pattern = re.compile(r"^### Client (.+)$")
    with open(f"/etc/wireguard/{server_wg_nic}.conf", "r") as f:
        lines = f.readlines()

    client_name = client_pattern.match(lines[client_number - 1]).group(1)

    # Удаление [Peer] блока, соответствующего имени клиента
    with open(f"/etc/wireguard/{server_wg_nic}.conf", "r") as f:
        lines = f.readlines()

    with open(f"/etc/wireguard/{server_wg_nic}.conf", "w") as f:
        for line in lines:
            if not line.strip().startswith("### Client") or not line.strip().endswith(client_name):
                f.write(line)

    # Удаление сгенерированного файла клиента
    client_conf_file = f"/root/{server_wg_nic}-client-{client_name}.conf"
    os.remove(client_conf_file)

    # Синхронизация конфигурации с помощью утилиты wg
    subprocess.run(["wg", "syncconf", server_wg_nic], input='', text=True)


def set_api_base():
    global api_base
    api_base = input("Введите базовый URL API: ")


def cloak_list_all_users():
    set_api_base()
    endpoint = f"http://{api_base}/admin/users"
    try:
        response = requests.get(endpoint)
        response.raise_for_status()
        data = response.json()
        for uinfo in data:
            print(uinfo)  # Здесь можно выполнить любую другую операцию с данными пользователей
        return data
    except requests.exceptions.RequestException as e:
        print("Ошибка при выполнении запроса:", e)


def cloak_delete_user():
    users = cloak_list_all_users()
    if not users:
        print("Нет доступных пользователей для удаления.")
        return

    while True:
        try:
            choice = int(input("Введите номер пользователя, которого хотите удалить (или 0 для отмены): "))
            if choice == 0:
                print("Отменено.")
                return
            if choice < 1 or choice > len(users):
                print("Неверный номер пользователя. Пожалуйста, введите корректный номер или 0 для отмены.")
                continue
            uid = users[choice - 1]['UID']
            endpoint = f"http://{api_base}/admin/users/{base64.urlsafe_b64encode(uid.encode()).decode()}"
            response = requests.delete(endpoint)
            response.raise_for_status()
            print(f"Пользователь {uid} успешно удален.")
            break
        except (ValueError, requests.exceptions.RequestException) as e:
            print("Ошибка:", e)


def generate_uid():
    uid = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    return uid


def show_add_user():
    uid = generate_uid()
    print("Сгенерированный UID для нового пользователя:", uid)
    # Здесь можно предположить, что пользователь вводит остальные данные для создания пользователя


def cloak_add_user():
    userinfo = {
        "UID": input("Введите UID пользователя: "),
        "SessionsCap": int(input("Введите максимальное количество сессий: ")),
        "UpRate": int(input("Введите скорость загрузки (в Мб/с): ")) * 1048576,
        "DownRate": int(input("Введите скорость скачивания (в Мб/с): ")) * 1048576,
        "UpCredit": int(input("Введите кредит для загрузки (в Мб): ")) * 1048576,
        "DownCredit": int(input("Введите кредит для скачивания (в Мб): ")) * 1048576,
        "ExpiryTime": int(input("Введите срок действия (в секундах): "))
    }
    endpoint = f"http://{api_base}/admin/users/{base64.urlsafe_b64encode(userinfo['UID'].encode()).decode()}"
    try:
        response = requests.post(endpoint, json=userinfo)
        response.raise_for_status()
        print("Пользователь успешно добавлен.")
    except requests.exceptions.RequestException as e:
        print("Ошибка при выполнении запроса:", e)


def openvpn_add_user():
    print("")
    print("Tell me a name for the client.")
    print("The name must consist of alphanumeric characters. It may also include an underscore or a dash.")

    client = input_user_name()

    print("")
    print("Do you want to protect the configuration file with a password?")
    print("(e.g. encrypt the private key with a password)")

    client_exists = check_user_exists(client)
    if client_exists:
        print("")
        print("The specified client CN was already found in easy-rsa, please choose another name.")
        return
    else:
        os.chdir("/etc/openvpn/easy-rsa/")
        os.system(f"./easyrsa build-client-full {client} nopass")
        print(f"Client {client} added.")

    home_dir = get_home_directory(client)
    tls_sig = get_tls_signature()

    with open("/etc/openvpn/client-template.txt", "r") as template_file:
        template = template_file.read()

    with open(os.path.join(home_dir, f"{client}.ovpn"), "w") as client_file:
        client_file.write(template)
        client_file.write("\n<ca>\n")
        with open(f"/etc/openvpn/easy-rsa/pki/ca.crt", "r") as ca_file:
            client_file.write(ca_file.read())
        client_file.write("\n</ca>\n\n<cert>\n")
        with open(f"/etc/openvpn/easy-rsa/pki/issued/{client}.crt", "r") as cert_file:
            client_file.write(cert_file.read())
        client_file.write("\n</cert>\n\n<key>\n")
        with open(f"/etc/openvpn/easy-rsa/pki/private/{client}.key", "r") as key_file:
            client_file.write(key_file.read())
        client_file.write("\n</key>\n")

        if tls_sig == "1":
            client_file.write("\n<tls-crypt>\n")
            with open("/etc/openvpn/tls-crypt.key", "r") as tls_crypt_file:
                client_file.write(tls_crypt_file.read())
            client_file.write("\n</tls-crypt>\n")
        elif tls_sig == "2":
            client_file.write("key-direction 1\n")
            client_file.write("\n<tls-auth>\n")
            with open("/etc/openvpn/tls-auth.key", "r") as tls_auth_file:
                client_file.write(tls_auth_file.read())
            client_file.write("\n</tls-auth>\n")

    print("")
    print(f"The configuration file has been written to {home_dir}/{client}.ovpn.")
    print("Download the .ovpn file and import it in your OpenVPN client.")
    return


def input_user_name():
    while True:
        client = input("Client name: ")
        if re.match(r'^[a-zA-Z0-9_-]+$', client):
            return client
        else:
            print(
                "Invalid client name. Please enter a name consisting of alphanumeric characters, underscores, or dashes.")


def check_user_exists(client):
    with open("/etc/openvpn/easy-rsa/pki/index.txt", "r") as index_file:
        for line in index_file:
            if re.match(fr"/CN={client}\$", line):
                return True
    return False


def get_home_directory(client):
    if os.path.exists(f"/home/{client}"):
        return f"/home/{client}"
    elif os.environ.get("SUDO_USER"):
        sudo_user = os.environ.get("SUDO_USER")
        if sudo_user == "root":
            return "/root"
        else:
            return f"/home/{sudo_user}"
    else:
        return "/root"


def get_tls_signature():
    with open("/etc/openvpn/server.conf", "r") as server_conf_file:
        server_conf = server_conf_file.read()
        if "tls-crypt" in server_conf:
            return "1"
        elif "tls-auth" in server_conf:
            return "2"
        else:
            return ""


def openvpn_delete_user():
    index_file = "/etc/openvpn/easy-rsa/pki/index.txt"

    # Проверяем наличие существующих клиентов
    with open(index_file) as f:
        number_of_clients = sum(1 for line in f if line.startswith("V\n"))

    if number_of_clients == 0:
        print("You have no existing clients!")
        exit(1)

    print("Select the existing client certificate you want to revoke:")
    with open(index_file) as f:
        clients = [line.split("=")[1].strip() for line in f if line.startswith("V")]

    for i, client in enumerate(clients, start=1):
        print(f"{i}) {client}")

    while True:
        client_number = input(f"Select one client [1-{number_of_clients}]: ")
        if client_number.isdigit() and 1 <= int(client_number) <= number_of_clients:
            client_number = int(client_number)
            break
        print("Invalid input. Please enter a number between 1 and", number_of_clients)

    client_to_revoke = clients[client_number - 1]

    # Revoke the client certificate
    os.chdir("/etc/openvpn/easy-rsa/")
    subprocess.run(["./easyrsa", "--batch", "revoke", client_to_revoke], check=True)
    subprocess.run(["./easyrsa", "gen-crl"], check=True)
    subprocess.run(["cp", "/etc/openvpn/easy-rsa/pki/crl.pem", "/etc/openvpn/crl.pem"], check=True)
    os.chmod("/etc/openvpn/crl.pem", 0o644)

    # Delete client configuration files
    for root, dirs, files in os.walk("/home/"):
        for file in files:
            if file.endswith(f"{client_to_revoke}.ovpn"):
                os.remove(os.path.join(root, file))
    os.remove(f"/root/{client_to_revoke}.ovpn")

    # Remove client from ipp.txt
    with open("/etc/openvpn/ipp.txt", "r+") as f:
        lines = f.readlines()
        f.seek(0)
        for line in lines:
            if not line.startswith(client_to_revoke):
                f.write(line)
        f.truncate()

    # Backup index.txt
    subprocess.run(["cp", "/etc/openvpn/easy-rsa/pki/index.txt", "/etc/openvpn/easy-rsa/pki/index.txt.bk"])

    print(f"\nCertificate for client {client_to_revoke} revoked.")


def openvpn_list_all_users():
    index_file_path = "/etc/openvpn/easy-rsa/pki/index.txt"
    if not os.path.exists(index_file_path):
        print("Index file not found. Make sure the path is correct.")
        return

    with open(index_file_path, "r") as index_file:
        clients = []
        for line in index_file.readlines()[1:]:
            if line.startswith("V"):
                client_info = line.split("=")[1].strip()
                clients.append(client_info)
    for i, client in enumerate(clients, start=1):
        print(f"{i}) {client}")


def main():
    if len(sys.argv) != 3:
        print("Incorrect format of input")
        return

    name = sys.argv[1]
    command = sys.argv[2]

    if name == "OpenVPN":
        if command == "add":
            openvpn_add_user()
        elif command == "delete":
            openvpn_delete_user()
        elif command == "list":
            openvpn_list_all_users()
        else:
            print("Unknown command")
    elif name == "Cloak":
        if command == "add":
            cloak_add_user()
        elif command == "delete":
            cloak_delete_user()
        elif command == "list":
            cloak_list_all_users()
        else:
            print("Unknown command")
    elif name == "Wireguard":
        if command == "add":
            wireguard_add_user()
        elif command == "delete":
            wireguard_delete_user()
        elif command == "list":
            wireguard_list_all_users()
        else:
            print("Unknown command")
    
    else:
        print("Invalid name:", name)


if __name__ == "__main__":
    main()
