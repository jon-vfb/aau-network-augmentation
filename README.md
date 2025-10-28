## 🚀 How to Contribute

To keep the project organized, we use a Git workflow. Please follow these steps to contribute.

---

### Our Workflow

We use an integration branch called **`QA`**. All development happens in feature branches that are based on `QA`.
No one should ever commit directly to `main` or `QA`.

**The flow is:**
`main` (Stable) ← `QA` (Testing) ← `feature/your-branch` (Development)

---

### 1. Start Your Work (Always sync first)

Before writing any code, make sure you have the latest version of the `QA` branch.

```bash
# 1. Switch to the QA branch
git checkout QA

# 2. Pull the latest updates
git pull
```

---

### 2. Create Your Feature Branch

Once you’ve synced with `QA`, create a new branch for your work, (e.g. `feature/validation` or `fix/merging_strategy`).

```bash
# 1. Create a new branch from QA
git checkout -b feature/your-branch-name
```

---

### 3. Work on Your Code

Make your changes, add your commits, and keep them clear and meaningful.

```bash
# Stage your changes
git add .

# Commit your work
git commit -m "Add: new login form with validation"
```

---

### 4. Sync with QA Regularly

Before pushing your branch, make sure it’s up to date with the latest `QA`.
This helps avoid conflicts later when opening a pull request.

```bash
# 1. Switch to QA
git checkout QA

# 2. Pull the latest changes
git pull

# 3. Switch back to your feature branch
git checkout feature/your-branch-name

# 4. Merge QA into your branch
git merge QA
```

```
It also works if from your working branch you execute: git pull origin QA
```

If there are conflicts, resolve them locally and commit the fixes.

---

### 5. Push Your Branch

Once your branch is ready (and tested locally), push it to the remote repository.

```bash
git push origin feature/your-branch-name
```

---

### 6. Open a Pull Request

Go to GitHub, open a **Pull Request** from your feature branch into `QA`,

After review and approval, your code will be merged into `QA`.
Later, once `QA` passes all tests, it will be merged into `main`.

