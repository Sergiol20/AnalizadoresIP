import tkinter as tk
from tkinter import filedialog
from tkinter import ttk
import re

hash_table ={}
def lexico_ipv4(cadena, index):
    # Expresión regular para IPv4 (con rango 0-255)
    regex_ipv4_byte = r'25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}'
    regex_ipv4_sep = r'\.'

    ipv4_tokens = re.findall(f'({regex_ipv4_byte}|{regex_ipv4_sep}|[^0-9])', cadena)
    tokens = []
    row, column = index, 1
    for token in ipv4_tokens:
        if re.match(regex_ipv4_byte, token):
            tokens.append((token, "Byte", row, column))
        elif re.match(regex_ipv4_sep, token):
            tokens.append((token, "Punto", row, column))
        elif token == ":":
            tokens.append((token, "DosPuntos", row, column))
        else:
            tokens.append((token, "?", row, column))
        column += len(token)
    return tokens


# Función para el análisis sintáctica de IPv4
def sintaxis_ipv4(ipv4_tokens):
    # Verificar si hay exactamente 4 tokens y que todos sean "Byte" o "Punto"
    if len(ipv4_tokens) != 7 or not all(token[1] in ["Byte", "Punto"] for token in ipv4_tokens):
        return False

    # Verificar que los "Byte" estén separados por "Punto" y tengan valores válidos
    byte_tokens = [token[0] for token in ipv4_tokens if token[1] == "Byte"]

    for i in range(len(ipv4_tokens)):
        if i % 2 == 0:
            if ipv4_tokens[i][1] != "Byte":
                return False
        else:  # Índices impares deben ser puntos
            if ipv4_tokens[i][1] != "Punto":
                return False


    if len(byte_tokens) != 4:
        return False

    # Verificar que los valores de los "Byte" estén en el rango 0-255
    for byte in byte_tokens:
        if not (0 <= int(byte) <= 255):
            return False

    return True



def lexico_ipv6(cadena, index):

    # Expresión regular para capturar tokens no identificados
    regex_ipv6_segmento = r'[0-9A-Fa-f]{1,4}'
    regex_ipv6_dp = r':'
    ipv6_tokens = re.findall(f'({regex_ipv6_segmento}|{regex_ipv6_dp}|[^0-9A-Fa-f:])', cadena)
    tokens =[]
    row, column = index, 1
    for token in ipv6_tokens:
        if re.match(regex_ipv6_segmento, token):
            tokens.append((token, "Segmento", row, column))
        elif re.match(regex_ipv6_dp, token):
            tokens.append((token, "DosPuntos", row, column))
        elif token == ".":
            tokens.append((token, "Punto", row, column))
        else:
            tokens.append((token, "?", row, column))
        column += len(token)

    return tokens


# Función para el análisis sintáctico de IPv6
def sintaxis_ipv6(ipv6_tokens):
    if len(ipv6_tokens) != 15 or ipv6_tokens[0][1] == "DosPuntos" or ipv6_tokens[-1][1] == "DosPuntos":
        return False

    for i in range(len(ipv6_tokens)):
        if i % 2 == 0:  # Índices pares deben ser segmentos
            if ipv6_tokens[i][1] != "Segmento":
                return False
            if len(ipv6_tokens[i][0]) > 4:
                return False
        else:  # Índices impares deben ser dos puntos
            if ipv6_tokens[i][1] != "DosPuntos":
                return False

    return True

def lexico_ipv6_dual(cadena, index):
    last_index = max(cadena.rfind(":"), max(cadena.rfind(c) for c in "abcdefABCDEF"))

    ipv6_part = cadena[:last_index + 1]
    ipv4_part = cadena[last_index + 1:]

    regex_ipv6_segmento = r'[0-9A-Fa-f]{1,4}'
    regex_ipv6_dp = r':'
    regex_ipv4_byte = r'25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}'
    regex_ipv4_sep = r'\.'

    ipv6_tokens = re.findall(f'({regex_ipv6_segmento}|{regex_ipv6_dp}|[^0-9A-Fa-f:])', ipv6_part)
    ipv4_tokens = re.findall(f'({regex_ipv4_byte}|{regex_ipv4_sep}|[^0-9])', ipv4_part)

    tokens = []
    row, column = index, 1

    for token in ipv6_tokens:
        if re.match(regex_ipv6_segmento, token):
            tokens.append((token, "Segmento", row, column))
        elif re.match(regex_ipv6_dp, token):
            tokens.append((token, "DosPuntos", row, column))
        elif token == ".":
            tokens.append((token, "Punto", row, column))
        else:
            tokens.append((token, "?", row, column))
        column += len(token)

    for token in ipv4_tokens:
        if re.match(regex_ipv4_byte, token):
            tokens.append((token, "Byte", row, column))
        elif re.match(regex_ipv4_sep, token):
            tokens.append((token, "Punto", row, column))
        elif token == ":":
            tokens.append((token, "DosPuntos", row, column))
        else:
            tokens.append((token, "?", row, column))
        column += len(token)

    return tokens

def sintaxis_ipv6_dual(ipv6_dual_tokens):
    if len(ipv6_dual_tokens) != 19:
        return False

    ipv6_part_tokens = ipv6_dual_tokens[:12]
    if not all(token[1] in ["Segmento", "DosPuntos", "?"] for token in ipv6_part_tokens):
        return False
    for i in range(len(ipv6_part_tokens)):
        if i % 2 == 0:  # Índices pares deben ser segmentos
            if ipv6_part_tokens[i][1] != "Segmento":
                return False
            if len(ipv6_part_tokens[i][0]) > 4:
                return False
        else:  # Índices impares deben ser dos puntos
            if ipv6_part_tokens[i][1] != "DosPuntos":
                return False

    ipv4_part_tokens = ipv6_dual_tokens[12:]
    if not all(token[1] in ["Byte", "Punto", "?"] for token in ipv4_part_tokens):
        return False

    for i in range(len(ipv4_part_tokens)):
        if i % 2 == 0:  # Índices pares deben ser segmentos
            if ipv4_part_tokens[i][1] != "Byte":
                return False
            if len(ipv4_part_tokens[i][0]) > 3:
                return False
        else:  # Índices impares deben ser dos puntos
            if ipv4_part_tokens[i][1] != "Punto":
                return False

    return True

def tokens_to_hash_table(tokens):

    for token, name, row, column in tokens:
        if name != "?":
            key = (row, column)
            value = f"{name} {token}"

            if key in hash_table:
                hash_table[key].append(value)
            else:
                hash_table[key] = [value]

    return hash_table



def verificar_ips_desde_archivo(archivo_path):
    hash_table.clear()
    index = 1
    errores = []

    with open(archivo_path, 'r') as archivo:
        contenido = archivo.read()

    elementos = contenido.split(',')
    elementos = [elemento.strip() for elemento in elementos]


    for ip in elementos:
        tokens = lexico_ipv4(ip, index)
        is_valid_ipv4 = sintaxis_ipv4(tokens)
        if is_valid_ipv4:
            resultado = f"{index}. {ip}"
        else:
            tokens = lexico_ipv6(ip, index)
            is_valid_ipv6 = sintaxis_ipv6(tokens)
            if is_valid_ipv6:
                resultado = f"{index}. {ip}"
            else:
                tokens = lexico_ipv6_dual(ip, index)
                is_valid_ipv6_dual = sintaxis_ipv6_dual(tokens)
                if is_valid_ipv6_dual:
                    resultado = f"{index}. {ip}"
                else:
                    resultado = f"{index}. {ip}"
                    errores.append(f"Error sintáctico en la fila {index}, cadena no válida: {ip}")
                    for token, name, row, column in tokens:
                        if name == "?":
                            errores.append(f"Error léxico en la fila {row} y columna {column}, valor no identificado: {token}")

        tokens_to_hash_table(tokens)
        index += 1

        # Mostrar el resultado en el Text
        resultado_text.config(state=tk.NORMAL)
        resultado_text.tag_configure("arial", font=("Arial", 12))
        resultado_text.insert(tk.END, resultado + "\n", "arial")
        resultado_text.config(state=tk.DISABLED)
        resultado_text.tag_configure("arial_verde", font=("Arial", 12), foreground="#00423F")


    # Mostrar los errores
    resultado_text.config(state=tk.NORMAL)
    resultado_text.insert(tk.END, "\nErrores:\n", "arial_verde")
    for error in errores:
        resultado_text.insert(tk.END, error + "\n", "arial_verde")
    resultado_text.config(state=tk.DISABLED)

def mostrar_hash_table():
    if hash_table:
        hash_table_window = tk.Toplevel()
        hash_table_window.title("Tabla Hash")

        tree = ttk.Treeview(hash_table_window, columns=("Fila", "Columna", "Nombre", "Valor"), show="headings", height=10)
        tree.heading("Fila", text="Fila", anchor=tk.W)
        tree.heading("Columna", text="Columna", anchor=tk.W)
        tree.heading("Nombre", text="Nombre", anchor=tk.W)
        tree.heading("Valor", text="Valor", anchor=tk.W)

        for key, values_list in hash_table.items():
            row, column = key
            for value in values_list:
                name, token = value.split(" ", 1)
                tree.insert("", "end", values=(row, column, name, token))

        tree.pack(fill="both", expand=True)

        # Aumentar el tamaño de la letra en los encabezados y celdas
        style = ttk.Style()
        style.configure("Treeview.Heading", font=("Arial", 12))  # Encabezados
        style.configure("Treeview", font=("Arial", 12))  # Celdas




def auto_scroll(tree, first, last):
    tree.yview_moveto(first)

def abrir_archivo():
    archivo_path = filedialog.askopenfilename(filetypes=[('Archivos de texto', '*.txt')])
    if archivo_path:
        resultado_text.config(state=tk.NORMAL)
        resultado_text.delete(1.0, tk.END)
        resultado_text.config(state=tk.DISABLED)
        verificar_ips_desde_archivo(archivo_path)


# Configurar la interfaz gráfica
window = tk.Tk()
window.title("Verificación de Direcciones IP desde Archivo")
window.state('zoomed')

titulo_grande = tk.Label(window, text="Validación de Direcciones IP Privadas", font=("Montserrat", 24), foreground="#338B85")

titulo_grande.pack()
ip_label = tk.Label(window, text="Seleccione un archivo de texto con direcciones IP:",font=("Ahroni", 12))
ip_label.pack()


estilo = ttk.Style()
estilo.configure("RoundedButton.TButton",
                 font=("Ahroni", 12),   # Tipo de letra y tamaño
                 borderwidth=5,
                 relief="groove",
                 padding=(10, 5))

open_file_button = ttk.Button(window, text="Abrir Archivo", style="RoundedButton.TButton",command=abrir_archivo)

open_file_button.pack(pady=20, padx=40)


resultado_text = tk.Text(window, wrap=None, width=120, height=35)
resultado_text.pack()
resultado_text.pack_propagate(False)
resultado_text.config(state=tk.DISABLED)

show_hash_button = ttk.Button(window, text="Mostrar Tabla de Simbolos", style="RoundedButton.TButton",command=mostrar_hash_table)
show_hash_button.pack(pady=20, padx=40)

window.mainloop()