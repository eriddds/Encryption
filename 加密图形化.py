import PySimpleGUI as sg
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
import base64

# 加密函数
def encrypt_message(message, password):
    salt = get_random_bytes(16)
    key = scrypt(password, salt, 32, N=2**14, r=8, p=1)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    encrypted_message = base64.b64encode(salt + cipher.nonce + tag + ciphertext).decode()
    return encrypted_message

# 解密函数
def decrypt_message(encrypted_message, password):
    encrypted_message = base64.b64decode(encrypted_message)
    salt = encrypted_message[:16]
    nonce = encrypted_message[16:32]
    tag = encrypted_message[32:48]
    ciphertext = encrypted_message[48:]
    key = scrypt(password, salt, 32, N=2**14, r=8, p=1)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    message = cipher.decrypt_and_verify(ciphertext, tag)
    return message.decode()

# GUI布局
layout = [
    [sg.Text("请选择操作：")],
    [sg.Radio('加密', "RADIO1", default=True, key='-ENCRYPT-'), sg.Radio('解密', "RADIO1", key='-DECRYPT-')],
    [sg.Text('请输入密码：'), sg.InputText(key='-PASSWORD-', password_char='*')],
    [sg.Text('请输入消息或加密文本：'), sg.Multiline(key='-INPUT-', size=(40, 5))],
    [sg.Text('结果：                          '), sg.Multiline(key='-OUTPUT-', size=(40, 5), disabled=True)],
    [sg.Button('开始', key='-START-'), sg.Button('退出', key='-EXIT-')]
]

# 创建窗口
window = sg.Window('加密与解密程序', layout)

# 事件循环
while True:
    event, values = window.read()

    if event == sg.WIN_CLOSED or event == '-EXIT-':
        break

    if event == '-START-':
        password = values['-PASSWORD-'].strip()
        input_text = values['-INPUT-'].strip()

        if not password or not input_text:
            sg.popup_error("密码和消息不能为空！")
            continue

        if values['-ENCRYPT-']:  # 加密模式
            try:
                encrypted_text = encrypt_message(input_text, password)
                window['-OUTPUT-'].update(encrypted_text)
            except Exception as e:
                sg.popup_error(f"加密失败：{str(e)}")

        elif values['-DECRYPT-']:  # 解密模式
            try:
                decrypted_text = decrypt_message(input_text, password)
                window['-OUTPUT-'].update(decrypted_text)
            except Exception as e:
                sg.popup_error(f"解密失败：{str(e)}\n可能是密码错误或数据已被篡改")

window.close()
