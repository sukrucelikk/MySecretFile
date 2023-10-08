from tkinter import *
from tkinter import messagebox
from PIL import Image, ImageTk
import base64

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)




window = Tk()
window.title("Secret File")
window.config(padx=30,pady=30)

img = ImageTk.PhotoImage(Image.open("image4.png"))
panel = Label(window, image = img)
panel.config(padx=20,pady=20)
panel.pack()


label = Label(text="Enter Your Title",font=('Arial',12,"normal"))
label.config(padx=10,pady=10)
label.pack()


entry = Entry(width=40)
entry.pack()

label2 = Label(text="Enter Your Secret",font=('Arial',12,"normal"))
label2.config(padx=10,pady=20)
label2.pack()

def button_clicked():
    title = entry.get()
    message = text.get("1.0",END)
    master_secret = entry2.get()

    if len(title) == 0 or len(message) == 0 or len(master_secret) == 0:
        messagebox.showinfo(title="Error!", message="Please enter all info.")

    else:
        #encryption
        encrypted_message = encode(master_secret, message)

        try:
            with open("Secret File.txt","a") as data_file:
                data_file.write(f"\n{title}\n{encrypted_message}")

        except FileNotFoundError:
            with open("Secret File.txt","w") as data_file:
                data_file.write(f"\n{title}\n{encrypted_message}")

        finally:
            entry.delete(0, END)
            entry2.delete(0, END)
            text.delete("1.0", END)

def button_clicked2():
    message_encrypted = text.get("1.0", END)
    master_secret = entry2.get()

    if len(message_encrypted) == 0 or len(master_secret) == 0:
        messagebox.showinfo(title="Error!", message= "Please enter all info.")
    else:
        try:
            message_decrypted = decode(master_secret, message_encrypted)
            text.delete("1.0", END)
            text.insert("1.0", message_decrypted)
        except:
            messagebox.showinfo(title="Error!", message="Please enter encrypted text!")



text = Text(width=35,height=15)
text.config(padx=10,pady=10)
text.pack()

label3 = Label(text="Enter Master Key",font=('Arial',12,"normal"))
label3.config(padx=10,pady=10)
label3.pack()

entry2 = Entry(width=40)
entry2.pack()

button = Button(text="Save & Encrypt",command= button_clicked)
button.config(pady=5,padx=5)
button.pack()

button2 = Button(text="Decrypt",command=button_clicked2)
button2.config(pady=5,padx=5)
button2.pack()



window.mainloop()