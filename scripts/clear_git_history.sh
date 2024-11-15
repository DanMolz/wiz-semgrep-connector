#!/bin/bash

# Step 1: Create a new orphan branch
git checkout --orphan new-branch

# Step 2: Add all files to the new branch
git add -A

# Step 3: Commit the changes
git commit -m "Initial commit"

# Step 4: Delete the old branch
git branch -D master

# Step 5: Rename the new branch to the original branch name
git branch -m master

# Step 6: Force push the new branch to the remote repository
git push -f origin master

echo "Git commit history cleared and pushed to remote repository."