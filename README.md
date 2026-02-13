
### Phase 2: Push to GitHub
1.  Go to **GitHub.com** and create a new repository 
2.  Open your terminal in the `site-inspector` folder.
3.  Run these commands to upload your code:
    ```bash
    git init
    git add .
    git commit -m "Initial commit"
    git branch -M main
    git remote add origin https://github.com/USERNAME/deep-inspector.git
    git push -u origin main
