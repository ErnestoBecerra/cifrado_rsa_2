from PySide6.QtWidgets import QApplication, QMainWindow, QPushButton, QTextEdit, QFileDialog, QMessageBox, QInputDialog
import sys
from PySide6.QtCore import Qt
from PySide6.QtGui import QPalette, QColor
import hashlib
import subprocess
import gnupg

CONFIG_FILE_PATH = "config.txt"  # Ruta del archivo de configuración

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("GARZÓN & SÁNCHEZ")
        self.setGeometry(100, 100, 800, 400)

        self.text_edit = QTextEdit(self)
        self.text_edit.setGeometry(20, 20, 560, 150)

        self.open_button = QPushButton("Abrir archivo", self)
        self.open_button.setGeometry(20, 230, 120, 60)
        self.open_button.clicked.connect(self.open_file_dialog)

        self.read_button = QPushButton("Leer archivo", self)
        self.read_button.setGeometry(150, 230, 120, 60)
        self.read_button.clicked.connect(self.read_file)

        self.generate_button = QPushButton("Generar archivo", self)
        self.generate_button.setGeometry(280, 230, 120, 60)
        self.generate_button.clicked.connect(self.generate_output_file)

        self.exit_button = QPushButton("Salir", self)
        self.exit_button.setGeometry(20, 300, 120, 60)
        self.exit_button.clicked.connect(self.close)

        self.verify_sha1_button = QPushButton("Verificar SHA", self)
        self.verify_sha1_button.setGeometry(150, 300, 120, 60)
        self.verify_sha1_button.clicked.connect(self.verify_sha1)

        self.generate_firm_button = QPushButton("Cifrar", self)
        self.generate_firm_button.setGeometry(600, 20, 120, 60)
        self.generate_firm_button.clicked.connect(self.cifrar_file)

        self.generate_firm_button = QPushButton("Descifrar", self)
        self.generate_firm_button.setGeometry(600, 100, 120, 60)
        self.generate_firm_button.clicked.connect(self.descifrar_file)

        self.generate_firm_button = QPushButton("Verificador", self)
        self.generate_firm_button.setGeometry(600, 180, 120, 60)
        self.generate_firm_button.clicked.connect(self.compare_files)

        self.selected_file_path = ""
        self.load_config()  # Cargar la ruta del archivo seleccionado desde el archivo de configuración


    def open_file_dialog(self):
        file_dialog = QFileDialog(self)
        file_dialog.setFileMode(QFileDialog.ExistingFile)
        file_dialog.setNameFilter("Archivos de texto (*.txt)")
        if file_dialog.exec():
            self.selected_file_path = file_dialog.selectedFiles()[0]
            self.save_config()
            with open(self.selected_file_path, "r") as file:
                self.text_edit.setPlainText(file.read())

    def read_file(self):
        if self.selected_file_path:
            with open(self.selected_file_path, "r") as file:
                content = file.read().replace('\n', ' ')
                self.text_edit.setPlainText(content)
                self.calculate_sha1(content)

    def calculate_sha1(self, content):
        sha1_hash = hashlib.sha1(content.encode()).hexdigest()
        self.text_edit.append(f" | {sha1_hash}")


    def generate_output_file(self):
        if self.selected_file_path:
            output_file_path = self.selected_file_path.replace(".txt", "_output.txt")
            content_2 = self.text_edit.toPlainText()
            content_2 = content_2.replace("\n", "")
            with open(output_file_path, "w") as file:
                file.write(content_2)
            self.text_edit.append("\nArchivo de salida generado.")
            

    
    def verify_sha1(self):
        if self.selected_file_path:
            output_file_path = self.selected_file_path.replace(".txt", "_output.txt")
            output_message_path = self.selected_file_path.replace(".txt", "_message.txt")  
            with open(output_file_path, "r") as file:
                lines = file.readlines()
                sha1_line = lines[-1].strip()
                file_content = "".join(lines[:-1]).strip()
                self.text_edit.setPlainText(file_content)
                split_content = sha1_line.split("|")[1].strip()
                split_content_2 = sha1_line.split("|")[0].strip()
                new_hash = hashlib.sha1(split_content_2.encode()).hexdigest()
            self.text_edit.append(f"Verificar:\nSHA-1: {split_content} \nNew SHA-1 : {new_hash}")

            
            if split_content == new_hash:
                QMessageBox.information(self,"Verificación", "SHA-1 válido \U0001F600", QMessageBox.Ok)
            else:
                QMessageBox.warning(self,"Verificación", "SHA-1 inválido \U0001F61E", QMessageBox.Ok)
                

    def cifrar_file(self):
        try:
            # Ruta del archivo de salida a cifrar
            output_file_path = "arch_cancion_output.txt"

            # Ruta del archivo de clave privada GPG
            private_key_file_path = "clave_privada.txt"

            
            with open(output_file_path, "r") as file:
                content = file.read()

            # Obtener el contenido antes del símbolo "|"
            content_before_symbol = content.split("|")[0]
            content_after_symbol = content.split("|")[1]

            self.text_edit.append(f"Mensaje a cifrar: \n{content_after_symbol}")

            # Comando para cifrar el archivo utilizando la clave privada
            command = ["gpg", "--sign", "--armor", "--local-user", "F9E5C1D4AEA15F8E", "--output", output_file_path + ".asc", "--yes"]

            # Ejecutar el comando utilizando subprocess
            subprocess.run(command, input=content_after_symbol, text=True)

            QMessageBox.information(self,"Cifrado", "Cifrado exitoso \U0001F600", QMessageBox.Ok)

        except Exception as e:
            print(f"Error al cifrar el archivo: {str(e)}")
            QMessageBox.warning(self,"Cifrado", "Error al cifrar \U0001F61E", QMessageBox.Ok)


    def descifrar_file(self):
        try:
            # Ruta del archivo cifrado
            encrypted_file_path = "arch_cancion_output.txt.asc"

            # Ruta del archivo de clave pública GPG
            public_key_file_path = "clave_publica.txt"

            # Comando para descifrar el archivo utilizando la clave pública
            command = ["gpg", "--batch", "--yes", "--output", "archivo_descifrado.txt", "--decrypt", "--recipient-file", public_key_file_path, encrypted_file_path]
            
            # Ejecutar el comando utilizando subprocess
            subprocess.run(command)
            QMessageBox.information(self,"Descifrado", "Descifrado con exitoso \U0001F600", QMessageBox.Ok)

        except Exception as e:
            print(f"Error al descifrar el archivo: {str(e)}")
            QMessageBox.warning(self,"Descifrado", "Error al descifrar \U0001F61E", QMessageBox.Ok)


    def compare_files(self):
        output_path = "arch_cancion_output.txt"
        decryp_file_path = "archivo_descifrado.txt"
        with open(output_path, "r") as ewe:
            content_3 = ewe.read()
        
        content_after_symbol = content_3.split("|")[1]

        with open(decryp_file_path,"r") as ewe_2:
            content_4 = ewe_2.read()
        
        self.text_edit.append(f"Verificar:\nSHA-1 original: {content_after_symbol} \nSHA-1 descifrado: {content_4}")

            
        if content_after_symbol == content_4:
            QMessageBox.information(self,"Verificación", "Son iguales \U0001F600", QMessageBox.Ok)
        else:
            QMessageBox.warning(self,"Verificación", "No son iguales \U0001F61E", QMessageBox.Ok)


    def save_config(self):
        with open(CONFIG_FILE_PATH, "w") as file:
            file.write(self.selected_file_path)

    def load_config(self):
        try:
            with open(CONFIG_FILE_PATH, "r") as file:
                self.selected_file_path = file.read()
        except FileNotFoundError:
            pass  # Si el archivo de configuración no existe, simplemente no se carga ninguna ruta previa


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
