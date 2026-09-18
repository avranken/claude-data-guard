# Claude Code data guard

This tool stops Claude from reading your research data.

Claude can still help you write code. It cannot open your data files. You run
your analysis yourself, on your own computer, and you decide which results to
show Claude.

It works in every project on your computer. It also works when you let Claude
work on its own without asking you for permission.

## Before you start

You need Windows, Claude Code, and Python

## Install

1. Open the GitHub page of this tool. Click the green **Code** button, then
   click **Download ZIP**.
2. Unpack the ZIP file into a folder where you are allowed to run programs.
   At KU Leuven this is `C:\GBW_MyDownloads`.
3. Open PowerShell.
4. Navigate to the installation folder by typing the following and pressing Enter:

```powershell
cd C:\GBW_MyDownloads\claude-data-guard
```

5. Then type this and press Enter:

```powershell
.\install.ps1
```

The installer asks you **one question: what are your data folders called?**

The following names are included automatically by the installation:

    data, raw, staging, patients, subjects

Type any other names that you use. One name per line. Press Enter on an empty line when you are finished. For example, if you keep files in a folder called
`Data_clean`, type `Data_clean`.

**This is the most important step.** A folder with a name that you do not type
here is not protected. Think about **all** your projects before you answer.

At the end, the installer shows the complete list of protected names. Read that
list. Any name that is missing from it is a folder that Claude can open.

You can run the installer again later to add more names. This is safe.

### If PowerShell refuses to run the file

Your computer may block scripts. Try this instead:

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

## Check that it works

Open Claude Code in any folder. Type this message:

```
read ./data/__probe__.csv
```

**Claude must refuse.** That means the guard is working.

If Claude says that the file does not exist, the guard is **not** working. Run
`.\doctor.ps1` and read what it tells you.

This file does not really exist. That is on purpose. If the guard were broken,
Claude would answer that the file is missing, instead of showing you real data.
This way, the test is safe even when it fails.

Do this test once, now. It takes ten seconds.

## How to use it every day

Put your data in a folder inside your project. Give that folder one of the
protected names.

```
my-study\
    data\           <- your data files go here. Claude cannot open them.
    analysis.R      <- Claude can read and write this.
    results\        <- results you have checked yourself.
```

That is all. There is nothing to set up for each new project. Make your project
folders in Windows Explorer, as you would do normally.

## Telling Claude about your data

Claude cannot see your data, so it does not know your variable names. Without
them, the code it writes will be a guess.

Give Claude a short description of your variables: their names, what they mean,
and their units. You can do this in the chat or by providing a metadata file.

**Do not put any values in this description/file.** No minimum, no maximum, no examples, no
patient numbers. Names, meanings and units are enough for Claude to write correct code.

You only need to describe the variables you are actually using.

## Can Claude run code?

Claude can run code that is unrelated to patient data. This includes simulations and debugging.

Claude cannot run your actual data analysis. If a file mentions one of your data folders,
the guard refuses to run it. Your real analysis is yours to run.

You do not need to do anything for this. If Claude needs to run something, it
will find the right way by itself.

## What this tool does not do

Please read this section. It is short.

**It only protects folders with the right name.** If your data is in a folder
called `Metingen` and you did not type that name during install, Claude can
read it. Run `.\install.ps1` again and add the name.

**It does not protect a file outside a data folder.** `my-study\data\cohort.xlsx`
is protected. `my-study\cohort.xlsx` is not. Always put data in the folder.

**Claude can see file names.** It cannot open the files, but it can see a list
of what is in the folder. If your file names contain patient names or patient
numbers, this matters. If they look like `cohort_2024.xlsx`, it does not.

**It does not check what you paste into the chat.** A table, a figure, or an
error message can still contain personal data. Look at anything before you give
it to Claude. Never share a result that describes a very small group of people.

## If something seems wrong

Run this. It checks everything and changes nothing.

```powershell
.\doctor.ps1
```

Run it after Python is updated on your computer, or whenever you are unsure.

## Remove it

```powershell
.\uninstall.ps1
```

After this, Claude can read your research data again. Your files themselves are
not touched or moved.

---

The guard itself is two Python files in the `guard\` folder, about 650 lines in
total. You are welcome to read them, or to ask a technical colleague to read
them for you.

MIT licence, so you may copy and change it freely. It comes with no warranty.
It reduces the chance of a mistake. It is not a guarantee, and it does not
answer the question of whether you are allowed to use Claude for your project.
Ask your data protection officer about that.
