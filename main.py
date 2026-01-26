import ctypes
#It allows Python to call functions and use features provided by the operating system (like Windows) that aren’t part of Python itself.
try:
    ctypes.windll.shcore.SetProcessDpiAwareness(1)  # Enable DPI awareness (Windows 8.1+)
except Exception:
    pass

import sys, os
#makes the gui text more clear and not blurry

import tkinter as tk 

from tkinter import ttk, messagebox, filedialog
# imports additional features

import re
# pattern based validation

import random
# python's random number and character generation module

import string
# python module that provides ready made sets like letters, digits, punctation

import sys, os

def resource_path(relative_path):
    """ Get absolute path to resource, works for PyInstaller """
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)


# --- Password strength logic --- #
# define a function named check_password_strength and takes the password as a parameter to check the stregnth of the password
def check_password_strength(password):
    issues = {
        "Too short (min 8 chars)": len(password) < 8, 
        #checks if the password is less than 8 characters long, true if too short, false if it's long enough

        "Missing uppercase letter": not re.search(r"[A-Z]", password), 
        # re.search looks for a pattern match inside the password

        "Missing lowercase letter": not re.search(r"[a-z]", password),
        # same idea, but now we are looking for strings that matches the lowercase letter from a-z

        "Missing number": not re.search(r"\d", password),
        # \d means any digit

        "Missing symbol (!@#$%^&* etc.)": not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)
        # and looking for specific symbols, in this case, we have to put the symbols we want to look for

    } # a dictionary of password problems and if they apply, issue description key: value (true or false result from condition), better 
      #alternative for if statements since i have to account for everything.
        
    score = 5 - sum(issues.values())
    # used to calculate the score, like a grading system 5 for strong and anything below a 3 is weak

    if score == 5:
        strength = "Strong", "green", 100
    elif score >= 3:
        strength = "Moderate", "orange", 60
    else:
        strength = "Weak", "red", 30
    # if and elif statements to just show the user if the passsword is strong or not

    return strength, [issue for issue, flag in issues.items() if flag]
    # returns how strong your password is, used for the GUI later

def generate_password(length=12):
    all_chars = string.ascii_letters + string.digits + "!@#$%^&*()_+"
    return ''.join(random.choice(all_chars) for _ in range(length))
    # define a function called generate_password and takes an optional parameter length, if no value is provided then the default length is 12

# --- Event Handlers --- # create a function called evaluate_password which runs when the user clicks the check strength button
def evaluate_password(): 
    password = entry.get() # retrieves the password the user typed in the entry field
    (level, color, value), issues = check_password_strength(password) 
    # calls the check_password_strength(password) function and unpacks the result

    result_label.config(text=f"Strength: {level}", fg=color)
    strength_bar["value"] = value
    # visually show how full the bar is based on your password strength
    strength_bar_style.configure("Color.Horizontal.TProgressbar", foreground=color, background=color)
    feedback = "\n".join(issues) if issues else "Looks good!"
    feedback_label.config(text=feedback)

    if password and password not in history:
        history.insert(0, password)
        if len(history) > 5:
            history.pop()
        update_history()
    # if password ensures we don't store empty inputs
    
    # defining a function to hide or show the password just for lil bit of privacy
def toggle_password_visibility():
    if entry.cget('show') == '':
        entry.config(show='*')
        toggle_btn.config(text='Hide')
    else:
        entry.config(show='')
        toggle_btn.config(text='Show')

    # fills the password with a freshly generated password when they click the generate password button
def insert_generated_password():
    new_password = generate_password()
    entry.delete(0, tk.END)
    entry.insert(0, new_password)

    # history box of the GUI to show a list of the latest passwords you've checked or created
def update_history():
    history_box.delete(0, tk.END)

    for pw in history:
        if history_visible:
            history_box.insert(tk.END, pw)
        else:
            history_box.insert(tk.END, "*" * len(pw))

def toggle_history_visibility():
    global history_visible
    history_visible = not history_visible

    if history_visible:
        history_toggle_btn.config(text="Hide History")
    else:
        history_toggle_btn.config(text="Show History")

    update_history()




    # This function checks if there's any password history
def export_history():
    if not history:
        messagebox.showinfo("Export History", "No passwords to export.")
        return

    # Open "Save As" dialog
    filepath = filedialog.asksaveasfilename(
        title="Save Password History",
        defaultextension=".txt",
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
    )

    # If user clicks Cancel, filepath will be empty
    if not filepath:
        return

    try:
        with open(filepath, "w") as f:
            for pw in history:
                f.write(pw + "\n")

        messagebox.showinfo("Export History", f"Saved successfully:\n{filepath}")
    except Exception as e:
        messagebox.showerror("Export History", f"Failed to save file:\n{e}")


    # copy feature
def copy_to_clipboard():
    pw = entry.get()
    if pw:
        root.clipboard_clear()
        root.clipboard_append(pw)
        messagebox.showinfo("Copied", "Password copied to clipboard!")
    else:
        messagebox.showwarning("Copy Failed", "No password to copy.")

def copy_from_history(event):
    selection = history_box.curselection()
    if not selection:
        return

    index = selection[0]
    real_password = history[index]

    root.clipboard_clear()
    root.clipboard_append(real_password)
    messagebox.showinfo("Copied", "Password copied from history!")


# --- GUI Setup ---
# Creates the main window for the GUI application to hold all other widgets (buttons, labels, etc.).
root = tk.Tk()
root.iconbitmap(resource_path("icon.ico"))
root.title("Password Strength Checker")
root.geometry("480x540")
root.resizable(False, False)

history = [] # for the password list
history_visible = False

# Creates a Label widget (text display)
tk.Label(root, text="Enter Password:", font=("Arial", 12)).pack(pady=(10, 5))
frame = tk.Frame(root)
frame.pack()

entry = tk.Entry(frame, width=30, font=("Arial", 11), show="")
entry.pack(side=tk.LEFT)

toggle_btn = tk.Button(frame, text="Hide", command=toggle_password_visibility)
toggle_btn.pack(side=tk.LEFT, padx=5)

# Buttons frame
btn_frame = tk.Frame(root)
btn_frame.pack(pady=8)

check_btn = tk.Button(btn_frame, text="Check Strength", command=evaluate_password)
check_btn.grid(row=0, column=0, padx=5)

generate_btn = tk.Button(btn_frame, text="Generate Password", command=insert_generated_password)
generate_btn.grid(row=0, column=1, padx=5)

copy_btn = tk.Button(btn_frame, text="Copy Password", command=copy_to_clipboard)
copy_btn.grid(row=1, column=0, padx=5, pady=5)

export_btn = tk.Button(btn_frame, text="Export History to File", command=export_history)
export_btn.grid(row=1, column=1, padx=5, pady=5)

ttk.Separator(root, orient="horizontal").pack(fill="x", pady=10)

# Strength Feedback
result_label = tk.Label(root, text="", font=("Arial", 12, "bold"))
result_label.pack()

strength_bar_style = ttk.Style()
strength_bar_style.theme_use("default")
strength_bar_style.configure("Color.Horizontal.TProgressbar", thickness=20)

strength_bar = ttk.Progressbar(root, style="Color.Horizontal.TProgressbar", length=350, mode="determinate", maximum=100)
strength_bar.pack(pady=5)

feedback_label = tk.Label(root, text="", font=("Arial", 10), fg="gray", wraplength=420, justify="left")
feedback_label.pack(pady=3)

ttk.Separator(root, orient="horizontal").pack(fill="x", pady=10)

# History
tk.Label(root, text="Last 5 Passwords Checked:", font=("Arial", 11, "bold")).pack(pady=(10, 3))
history_box = tk.Listbox(root, height=5, width=50)
history_box.pack()
history_box.bind("<Double-Button-1>", copy_from_history)

#history toggle button
history_toggle_btn = tk.Button(
    root,
    text="Show History",
    command=toggle_history_visibility,
    font=("Arial", 10),  # font size
    height=2,            # number of text lines tall
    width=15             # horizontal width in characters
)
history_toggle_btn.pack(pady=5)



# Starts the GUI and keeps it running until the user closes the window.
# Updates the interface in real-time as users interact with it.
root.mainloop()
