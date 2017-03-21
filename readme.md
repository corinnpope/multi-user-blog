# Multi-User Blog

## Introduction

> This is a simple blog website that allows multiple users to post blog posts and add comments. It includes basic authentication features and basic security features for users. 

## Requirements

This application was built to meet the following requirements:

+ App is built using Google App Engine


+ User is directed to login, logout, and signup pages as appropriate. E.g., login page should have a link to signup page and vice-versa; logout page is only available to logged in user.


+ Links to edit blog pages are available to users. Users editing a page can click on a link to cancel the edit and go back to viewing that page.

+ Blog pages render properly. Templates are used to unify the site.


+ Users are able to create accounts, login, and logout correctly.


+ Existing users can revisit the site and log back in without having to recreate their accounts each time.


+ Usernames are unique. Attempting to create a duplicate user results in an error message.


+ Stored passwords are hashed. Passwords are appropriately checked during login. User cookie is set securely.


+ Logged out users are redirected to the login page when attempting to create, edit, delete, or like a blog post.


+ Logged in users can create, edit, or delete blog posts they themselves have created.


+ Users should only be able to like posts once and should not be able to like their own post.


+ Only signed in users can post comments.

+ Users can only edit and delete comments they themselves have made.


+ Code follows the Google Python Style Guide.


+ Code follows an intuitive, easy-to-follow logical structure.


+ Code that is not intuitively readable is well-documented with comments.



+ Instructions on how to run the project are outlined in a README file.

## Installation

> The site can be accessed publicly at https://mublog-122333.appspot.com/

The site is hosted using google app engine. To set-up your own instance:
1. Install python
2. Install google app engine via https://cloud.google.com/appengine/downloads#Google_App_Engine_SDK_for_Python
3. Sign up for a google app engine account if you don't already have one at https://console.cloud.google.com/appengine/
4. Create a new project in the consol https://console.cloud.google.com/
5. Fork the code for this project and initialize your google app engine project. For some tips and a walkthrough of how to get started with Google App Engine, go to https://cloud.google.com/appengine/docs/python/quickstart. 
6. Deploy your project on the web using ` gcloud app deploy` or locally using `dev_appserver.py app.yaml`
