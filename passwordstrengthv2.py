import ctypes
#It allows Python to call functions and use features provided by the operating system (like Windows) that aren’t part of Python itself.
try:
    ctypes.windll.shcore.SetProcessDpiAwareness(1)  # Enable DPI awareness (Windows 8.1+)
except Exception:
    pass

import sys, os

#makes the gui text more clear and not blurry
# ctypes.windll is accessing Windows system libraries.
# shcore is a Windows system library that contains functions for handling screen-related settings.
# SetProcessDpiAwareness is a function that tells Windows how your program wants to handle DPI scaling.
# The 1 means “System DPI aware”, which works well for most apps on Windows 8.1 and later.
# The try-except block ensures your program doesn’t crash if this happens — it just quietly skips it.


import tkinter as tk 
# imports the base tkinter as tk, needed for the GUI window that 
# pops up when executed and widgets like buttons, labels, text boxes,
# name erorr when using tk.* components

from tkinter import ttk, messagebox, filedialog
# imports additional features from tkinter, we get ttk from tkinter
# i used it for the progress bar and the pop ups

import re
# regular expressions module, for pattern based validation, search for specific text patterns within strings

import random
# python's random number and character generation module
# for my random password generation feature (if the user can't think of a password)

import string
# python module that provides ready made sets like letters, digits, punctation
# using this to check what kind of characters the password includes (the one that the user makes), 
# i have to hardcode all the characters if i didnt use this


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
        # re.search looks for a pattern match inside the password, and not flips
        # the not is there so it makes the statement true by default.
        # there is uppercase letter --> false, if there isn't --> true
        # r makes it look for the raw string of the password, DO NOT ESCAPE BACKSLASHES, without it, "\n" is a newline but with r "\n" is two characters
        # so it looks for any string that matches the uppercase letter from A-Z

        "Missing lowercase letter": not re.search(r"[a-z]", password),
        # same idea, but now we are looking for strings that matches the lowercase letter from a-z
        # 
        "Missing number": not re.search(r"\d", password),
        # \d means any digit

        "Missing symbol (!@#$%^&* etc.)": not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)
        # and looking for specific symbols, in this case, we have to put the symbols we want to look for

    } # a dictionary of password problems and if they apply, issue description key: value (true or false result from condition), better 
      #alternative for if statements since i have to account for everything.
        
    score = 5 - sum(issues.values())
    # used to calculate the score, like a grading system 5 for strong and anything below a 3 is weak
    # after matching the patterns and getting all the true/false values,
    # the issue dictioanry should look like this for example
    # {
    # short: True,
    # missing uppercase: False,
    # missing lowercase: False,
    # missing number: True,
    # missing symbol: True
    # }
    # true = problem exist, false = no issues
    # issue.values() makes it so it returns a list of the true/false values 
    # ^ issues.values() → [True, False, False, True, True] --> and turns it into an integer to calculate the score
    # true = 1 and false = 0
    # ex: 3 trues, and 2 falses
    # 5 - 3 = 2 (right now 5 is the perfect score)
    # **you can change how "strong" or "weak" a password is if you add more things to check in a passwrod to scale it
    # 5 - amount of trues found
    if score == 5:
        strength = "Strong", "green", 100
    elif score >= 3:
        strength = "Moderate", "orange", 60
    else:
        strength = "Weak", "red", 30
    # if and elif statements to just show the user if the passsword is strong or not
    # a "tuple", used for the GUI later
    # self reminder: a tuple is like a list but it's ordered (indexable) and immutable (cant change values after creating it) and with ()
    # strength = (label, color, progress bar value)

    return strength, [issue for issue, flag in issues.items() if flag]
    # returns how strong your password is, used for the GUI later
    # by making a list [] of all issue descriptions where the password failed a rule.
    # temporary variable name, issue --> key in the dicitonary
    # flag --> the value (true or false)
    # goes through each item in issues, and if the flag (the value) is true, add issue to the list
    # issue for issue, flag in --> for each issue, include it in the lisst if the flag is true
    # if flag is a filter --> flag == True, issue is added to list, flag == False, it's skipped
    # in other words: creating a temporary variable called issue, 
    # and for each key-value pair (issue, flag) in issues.items(), if flag is True, then I add issue (the key) to a new list.
    # issue.items() returns all the key value pairs from the dict.

def generate_password(length=12):
    all_chars = string.ascii_letters + string.digits + "!@#$%^&*()_+"
    return ''.join(random.choice(all_chars) for _ in range(length))
    # define a function called generate_password and takes an optional parameter length, if no value is provided then the default length is 12
    # create a variable that stores all the characters that could appear in your password like:
    # string.ascii_letters --> [a-z] and [A-Z]
    # string.digits --> [0-9]
    # and the special characters !@#$%^&*()_+ and so on
    # ''.join(...) joins all the randomly picked characters into one single password string
    # random.choice(all_chars_) picks one random character from the string stored in the all_chars variable.
    # for _ in range(length) repeats that random string length times (12) --> learned something new! --> _ means idc bout this variable


# --- Event Handlers --- # create a function called evaluate_password which runs when the user clicks the check strength button
def evaluate_password(): 
    password = entry.get() # retrieves the password the user typed in the entry field
    (level, color, value), issues = check_password_strength(password) 
    # calls the check_password_strength(password) function and unpacks the result
    # level: stregth label, color: color regarding the pw strength, value: progress bar percentage
    # referring to the list of failed checks
    result_label.config(text=f"Strength: {level}", fg=color)
    # f-string (formatted string literal, a concise and efficient way to embed Python expressions inside string literals for formatting and interpolation)
    # and f"" lets me inject variables into a string using {for the variables}
    # fg --> foreground color
    # .config or .configure lets me update the widget settings after it has been created
    strength_bar["value"] = value
    # visually show how full the bar is based on your password strength
    strength_bar_style.configure("Color.Horizontal.TProgressbar", foreground=color, background=color)
    # strength_bar_style --> custom style from ttk
    # update the bar's foreground and background to the color based on strength
    # anyname.Horizontal.TProgressbar --> a horizontal progress bar and TProgressbar: type of widget being styled
    feedback = "\n".join(issues) if issues else "Looks good!"
    feedback_label.config(text=feedback)
    # is the feedback message and will join the issues into 1 string and if issues is empty (passed) and it says looks good.
    # if issue is not empty, add a new line with the issue to feedback, if it is empty then assigns the string looks good to feedback.
    # Combines all strings in the issues list into a single string, putting a newline \n between each one.
    # make a label that displays the string stored in feedback
    if password and password not in history:
        history.insert(0, password)
        if len(history) > 5:
            history.pop()
        update_history()
    # if password ensures we don't store empty inputs
    # If the password isn't empty and hasn't been checked before, 
    # add it to the top of the history list. If the list now has more than 5 passwords, 
    # remove the oldest one (at the end). Then update the on-screen password history.
    # if password checks if the password is not empty (empty is false and anything in it is true) and so this if statement only continues
    # if the user typed something
    # password not in history checks if the password is not already in the list of previously checked passwords
    # tldr: If the password is not empty AND hasn’t already been checked, then do the next steps.
    
    # defining a function to hide or show the password just for lil bit of privacy
def toggle_password_visibility():
    # entry is the password entry field --> where the user types in hte password
    # .cget --> config get --> retrieve value of 'show' (hiding your password) --> to know what mode it's currently in
    # entry.config(show='*') sets the password field to hide the characters with *
    # toggle_btn.config(text='Hide') changes the text on the button to hide
    # else, if the password is already hidden, this runs to reveal it
    if entry.cget('show') == '':
        entry.config(show='*')
        toggle_btn.config(text='Hide')
    else:
        entry.config(show='')
        toggle_btn.config(text='Show')

    # fills the password with a freshly generated password when they click the generate password button
    # entry (input box), tk.end --> end of entry and it's there to remove anything the user previously typed before the new password
    # inserts the newly generated passwrod into the input field, starting at index 0.
def insert_generated_password():
    new_password = generate_password()
    entry.delete(0, tk.END)
    entry.insert(0, new_password)

    # history box of the GUI to show a list of the latest passwords you've checked or created
    # history_box is the tk.Listbox used to display the latest 5 passwords and delete is there removes  everything from the lsitbox
    # for loop that creates a temprorary variable called item that represents one password in the list
    # tk.END --> Adds each password (item) into the history_box Listbox widget
    # added new feautre where the passwords are masked in the history
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




    # This function checks if there's any password history, 
    # and if so, it writes it to a text file on the user’s Desktop. 
    # If something goes wrong, it shows an error message.
    # checkss if the histroy list is empty (no passwords), not history is true whn list is empty
    # shows a pop up that there's no passwrods to save and return skips the rest of the code if empty
    # TRY IS THERE FOR SAFETY
    # import os interacts with the file system
    # desktop = os.path.join(os.path.expanduser("~"), "Desktop") --> builds the full file path to the Desktop for the current user
    # os.path.expanduser("~") gets the home directory (e.g., C:/Users/stanl)
    # os.path.join(..., "Desktop") appends Desktop to that path.
    # filepath = os.path.join(desktop, "password_history.txt") --> Creates the full path to the file you’ll save
    # with open(filepath, "w") as f --> Opens (or creates) the file in write mode ("w"), and stores it in a file object named f
    # "w" will overwrite any existing file with the same name.
    # with ensures the file is automatically closed after writing
    # for pw in history: --> Loops through each password stored in the history list, so each password can be written to its own line in the file.
    # f.write(pw + "\n") --> Writes one password per line to the file, using \n to move to a new line after each, so the file is nicely formatted and readable.
    # messagebox.showinfo("Export History", f"Password history saved as:\n{filepath}") --> Shows a success message box, letting the user know where the file was saved.
    # except Exception as e: If any error happens during the try block, this catches it and saves the error message as e.
    # messagebox.showerror("Export History", f"Failed to save: {e}") --> Displays an error popup with the actual problem that occurred.

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
    # pw = entry.get() --> Grabs the current text from the password entry field and stores it in a variable called pw
    # entry is the tk.Entry widget (where the password is typed/generated).
    # .get() means: “get the text the user entered.”
    # if pw: --> Checks if the password (pw) is not empty, pw returns True if pw contains anything.
    # root.clipboard_clear() --> Clears whatever was previously stored in the clipboard.
    # --> root is your main window (the tk.Tk() object). and .clipboard_clear() removes old clipboard contents.
    # root.clipboard_append(pw) --> Adds (appends) the password pw to the clipboard.
    # messagebox.showinfo("Copied", "Password copied to clipboard!") 
    # --> Pops up a little info message telling the user that the copy was successful.
    # --> "Copied" is the title of the window. and "Password copied to clipboard!" is the message.
    # else, if the password is empty (""), this block runs instead of the one above.
    # messagebox.showwarning("Copy Failed", "No password to copy.") --> "Copy Failed" = title  and "No password to copy." = message
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
# Creates the main window (also called the “root window”) for your GUI application to hold all other widgets (buttons, labels, etc.).
root = tk.Tk()
root.iconbitmap(resource_path("icon.ico"))
root.title("Password Strength Checker")
root.geometry("480x540")
root.resizable(False, False)

history = [] # for the password list
history_visible = False


# Entry
# Creates a Label widget (text display) inside the root window, Displays the text "Enter Password:" using Arial 12pt font
# Uses .pack(pady) to position it on the GUI with vertical padding.
# Creates a Frame widget—a container that can hold other widgets added directly to root
# Display the frame on the window using the pack layout manager.
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
