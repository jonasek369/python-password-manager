import json
from rich.console import Console
from rsa import newkeys, encrypt, decrypt, PrivateKey, PublicKey
import os
import time

KEYPAIR_EXTENSION = ".kp"
CWD = os.getcwd()


class PasswordManagerBackend:
    def __init__(self):
        if not os.path.exists(".local"):
            os.mkdir(".local")
        self.__public = None
        self.__private = None

    def are_keys_set(self) -> bool:
        return self.__public is not None and self.__private is not None

    def __generate_keypair_buffer(self):
        self.assert_keys_exists()
        # generates the buffer to go to file
        return f"""----PUBLIC KEY START----
{self.__public.n}
{self.__public.e}
----PUBLIC KEY END----
----PRIVATE KEY START----
{self.__private.n}
{self.__private.e}
{self.__private.d}
{self.__private.p}
{self.__private.q}
----PRIVATE KEY END----"""

    @staticmethod
    def generate_password_buffer(values):
        ijson = ",".join([f"'{key}':'{val}'" for key, val in values]).replace("'", '"')

        return json.dumps(json.loads("{" + ijson + "}"))

    @staticmethod
    def create_unique_file(file_name, file_extension, directory, data, write_mode="w"):
        if not file_extension.__contains__("."):
            file_extension = f".{file_extension}"
        if not directory.endswith("/"):
            directory = directory + "/"
        files = os.listdir(directory)
        if f"{file_name}{file_extension}" in files:
            file_instance = 1
            while True:
                if f"{file_name}({file_instance}){file_extension}" not in files:
                    break
                file_instance += 1
            with open(f"{directory}{file_name}({file_instance}){file_extension}", write_mode) as file:
                file.write(data)
        else:
            with open(f"{directory}{file_name}{file_extension}", write_mode) as file:
                file.write(data)

    # helper function
    def load_and_decrypt(self, filename):
        self.assert_keys_exists()
        with open(filename, "rb") as file:
            content = file.read()
        return json.loads(decrypt(content, self.__private).decode().replace("'", '"'))

    def generate_keypair(self, length, save_to_file):
        self.__public, self.__private = newkeys(length, True, 1)
        if save_to_file:
            files = os.listdir()
            buffer = self.__generate_keypair_buffer()
            if f"keypair{KEYPAIR_EXTENSION}" in files:
                not_occupied = 1
                while True:
                    if f"keypair({not_occupied}){KEYPAIR_EXTENSION}" in files:
                        not_occupied += 1
                    else:
                        break
                with open(f"keypair({not_occupied}){KEYPAIR_EXTENSION}", "w") as file:
                    file.write(buffer)
            else:
                with open(f"keypair{KEYPAIR_EXTENSION}", "w") as file:
                    file.write(buffer)
        else:
            raise Warning("You should always save your keypair into secure file")

    def set_keypair(self, file_name):
        with open(file_name, "r") as file:
            lines = file.readlines()
        # key pair has to have least 11 lines or its invalid, AssertionError
        assert len(lines) >= 11, "Keypair file dose not have enough of lines"
        public_start = None
        public_end = None
        private_start = None
        private_end = None
        for pos, line in enumerate(lines):
            if line.__contains__("----PUBLIC KEY START----"):
                public_start = pos + 1
            if line.__contains__("----PUBLIC KEY END----"):
                public_end = pos
            if line.__contains__("----PRIVATE KEY START----"):
                private_start = pos + 1
            if line.__contains__("----PRIVATE KEY END----"):
                private_end = pos
        # check if all key starts and ends are set. TypeError if not
        sum([public_start, public_end, private_start, private_end])

        public_n, public_e = [int(i) for i in lines[public_start:public_end]]
        private_n, private_e, private_d, private_p, private_q = [int(i) for i in lines[private_start:private_end]]
        self.__public = PublicKey(public_n, public_e)
        self.__private = PrivateKey(private_n, private_e, private_d, private_p, private_q)
        return True

    def autoload_keypair(self, filename):
        if filename.endswith(f"{KEYPAIR_EXTENSION}"):
            filename = filename[:len(filename) - len(KEYPAIR_EXTENSION)]
        with open(f"{filename}{KEYPAIR_EXTENSION}", "r") as file:
            lines = file.readlines()

        # key pair has to have least 11 lines or its invalid
        assert len(lines) >= 11, "Keypair file dose not have enough of lines"

        public_start = None
        public_end = None
        private_start = None
        private_end = None

        for pos, line in enumerate(lines):
            if line.__contains__("----PUBLIC KEY START----"):
                public_start = pos + 1
            if line.__contains__("----PUBLIC KEY END----"):
                public_end = pos
            if line.__contains__("----PRIVATE KEY START----"):
                private_start = pos + 1
            if line.__contains__("----PRIVATE KEY END----"):
                private_end = pos

        # check if all key starts and ends are set
        try:
            sum([public_start, public_end, private_start, private_end])
        except TypeError:
            print("Could not find all keys starts and ends in the file")

        public_n, public_e = [int(i) for i in lines[public_start:public_end]]
        private_n, private_e, private_d, private_p, private_q = [int(i) for i in lines[private_start:private_end]]
        self.__public = PublicKey(public_n, public_e)
        self.__private = PrivateKey(private_n, private_e, private_d, private_p, private_q)
        return True

    def load_passwords(self):
        self.assert_keys_exists()
        encrypted_files = os.listdir(".local")
        pwd_jsons = []
        for file in encrypted_files:
            try:
                pwd_jsons.append(self.load_and_decrypt(".local/" + file))
            except Exception as e:
                print(e)
        return pwd_jsons

    def save_password(self, filename, values):
        self.assert_keys_exists()
        values.append(("__file_display_name__", filename))
        json_buffer = self.generate_password_buffer(values)
        # Public key component N is getting wrongly calculated so its failing ?
        encrypted_content = encrypt(json_buffer.encode(), self.__public)
        self.create_unique_file("encrypted_data", ".encpwm", ".local/", encrypted_content, "wb")

    def assert_keys_exists(self):
        assert self.__public or self.__private, "keypair is not set"


def clear():
    os.system("cls")


class PasswordManagerFrontend:
    def __init__(self):
        clear()
        self.backend = PasswordManagerBackend()
        self.console = Console(color_system="truecolor", width=120, height=30)

    @staticmethod
    def evaluate_decision(user_input, type_wanted):
        user_input = user_input.lower()
        if type_wanted == bool:
            if user_input == "1" or user_input == "y" or user_input == "yes" or user_input == "true" or user_input == "t":
                return True
            if user_input == "0" or user_input == "n" or user_input == "no" or user_input == "false" or user_input == "f":
                return False
            else:
                raise Warning("Decision not recognized")
        if type_wanted == int:
            try:
                return int(user_input)
            except ValueError:
                raise Warning("Decision not recognized")
        if type_wanted == str:
            return user_input

    @staticmethod
    def get_all_keypair_files(directory) -> list:
        files = os.listdir(directory)
        if not directory.endswith("/"):
            directory = directory + "/"
        matching = []
        for file in files:
            if file.endswith(KEYPAIR_EXTENSION):
                matching.append(f"{directory}{file}")
        return matching

    def print_choices(self, choices, number_color="green"):
        for pos, choice in enumerate(choices):
            self.console.print(f"[[{number_color}]{pos + 1}[/]] {choice}")

    def password_board(self):
        decrypt_jsons = self.backend.load_passwords()
        decrypt_names = [i["__file_display_name__"] for i in decrypt_jsons]
        while True:
            self.console.clear()
            self.console.print("[[red]0[/]] Go back")
            self.print_choices(decrypt_names)
            decrypt_index = self.evaluate_decision(self.console.input("> "), int) - 1
            if decrypt_index == -1:
                return
            if decrypt_jsons[decrypt_index].get("__file_display_name__"):
                decrypt_jsons[decrypt_index].pop("__file_display_name__")
            self.console.clear()
            self.console.print_json(json.dumps(decrypt_jsons[decrypt_index]))
            self.console.input("Enter to go back to passwords")

    def decrypt_custom_file(self):
        self.console.clear()
        self.console.print("Select file to decrypt")
        path = self.evaluate_decision(self.console.input("> "), str)
        if not os.path.isfile(path):
            self.console.print("This is not an valid path to an file")
            time.sleep(5)
        output = self.backend.load_and_decrypt(path)
        self.console.print_json(json.dumps(output))
        self.console.input("Enter to go back")

    def encrypt_data(self):
        self.console.clear()
        self.console.print("Select the name of the file")
        file_name = self.evaluate_decision(self.console.input("> "), str)

        values = []
        while True:
            self.console.clear()
            self.print_choices(["finish", "add field"])
            decision = self.evaluate_decision(self.console.input("> "), int)
            if decision == 1:
                break
            if decision == 2:
                field_name = self.evaluate_decision(self.console.input("name the field > "), str)
                field_value = self.evaluate_decision(self.console.input("set the field value > "), str)
                values.append((field_name, field_value))
            else:
                continue
        self.backend.save_password(file_name, values)

    def run(self):
        self.console.show_cursor(False)
        self.console.set_window_title("Local Password Manager")

        DONT_SKIP_AUTOLOAD = True
        while True:
            self.console.clear()
            self.console.print("Local Password Manager", justify="center")
            keypair_set = self.backend.are_keys_set()
            if keypair_set:
                self.console.print("[green]Keypair is set!")
            else:
                self.console.print("[red]Keypair is not set!")
            # detect if user has keypair file in current folder and ask if user wants to use it
            if not keypair_set and len(self.get_all_keypair_files(CWD)) >= 1 and DONT_SKIP_AUTOLOAD:
                self.console.print("It looks like there is keypair in the directory.")
                self.console.print("Do you want to load these keys ?")
                load_keypair = self.evaluate_decision(self.console.input("> "), bool)
                if load_keypair:
                    self.console.clear()
                    kp_files = self.get_all_keypair_files(CWD)
                    self.console.print("Select which keypair file would you like to use.")
                    self.print_choices(kp_files)
                    file_index = self.evaluate_decision(self.console.input("> "), int) - 1

                    with self.console.status("Loading keypair", spinner="line"):
                        try:
                            self.backend.autoload_keypair(kp_files[file_index])
                            continue
                        except AssertionError:
                            self.console.log("Inputted file is not a valid keypair (waiting 10 seconds)")
                            time.sleep(4)
                            continue
                else:
                    DONT_SKIP_AUTOLOAD = False
                    continue
            if not keypair_set:
                self.print_choices(["Generate new keypair", "Load keypair from file"])
                keypair_decision = self.evaluate_decision(self.console.input("> "), int)
                # generates and saves new keypair
                if keypair_decision == 1:
                    # fast fix for now (Symmetric cipher for more data)
                    self.console.print("Select length of key recommended over 2048")
                    self.console.print("the higher key is the more data it can store")
                    self.console.print("but the longer it will take to generate")
                    # make the key minimal size 2048
                    length = max(2048, self.evaluate_decision(self.console.input("> "), int))
                    with self.console.status("Generating keypair", spinner="line"):
                        self.backend.generate_keypair(length, True)
                    continue
                # loads keypair from users file
                if keypair_decision == 2:
                    self.console.print("Select file to import keypair")
                    path = self.evaluate_decision(self.console.input("> "), str)
                    if not os.path.isfile(path):
                        self.console.print("This is not an valid path to an file")
                        time.sleep(5)
                        continue
                    try:
                        load_status = self.backend.autoload_keypair(path)
                    except (AssertionError, TypeError) as e:
                        if isinstance(e, AssertionError):
                            self.console.print("File did not have needed count of lines parsing could not start")
                        if isinstance(e, TypeError):
                            self.console.print("Could not find all the values that we needed")
                        time.sleep(5)
                        continue
            else:
                # print options when user has keypair set
                self.print_choices(["Encrypt data", "Decrypt data"])
                option_decision = self.evaluate_decision(self.console.input("> "), int)
                if option_decision == 1:
                    self.encrypt_data()
                if option_decision == 2:
                    self.console.clear()
                    self.print_choices(["Decrypt all in .local", "Decrypt custom file"])
                    decrypt_decision = self.evaluate_decision(self.console.input("> "), int)
                    if decrypt_decision == 1:
                        self.password_board()
                    if decrypt_decision == 2:
                        self.decrypt_custom_file()
                    else:
                        continue
                else:
                    continue


if __name__ == "__main__":
   PasswordManagerFrontend().run()
