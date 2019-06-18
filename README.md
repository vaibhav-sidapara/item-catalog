## Project: Item Catalog

#### Description
This is the fourth project in Udacity's Full Stack Web Developer Nanodegree Program.

The aim of this project is to deploy skills such as developing RESTful web applications that utilize python framework Flask along with OAuth authentication and implementation of CRUD based utilities to provide user friendly services. The code provided in this repository runs on a local server.

---
#### Things to have/do before running the code
##### System Requirements
This project makes use of Linux-based virtual machine (VM).
- [Vagrant](https://www.vagrantup.com/)
- [Oracle VM VirtualBox](https://www.virtualbox.org/)
- [Git](https://git-scm.com/)

##### System Setup 
1. Git Clone  [fullstack-nanodegree-vm](https://github.com/udacity/fullstack-nanodegree-vm)
    * Further Instructions provided on the above Udacity's repo on how to run the vagrant box.
    * Python & SQLite are already installed and started in the VM 
2. Git Clone this repo in your local directory such that it can be accessed from the vagrant machine via ssh
3. This app uses Google's OAuth 2.0 protocol for authentication and authorization.
    * Create an app project in the Google APIs Console — https://console.developers.google.com/apis
    * Create an OAuth Client ID.
    * When you're presented with a list of application types, choose Web application.
    * You can then set the **Authorized Javascript Origins** & **Authorised redirect URIs** 
        * To run this app on localhost set the above details as below
            - *Authorized Javascript Origins* : http://localhost:8000
            - *Authorised redirect URIs* : http://localhost:8000/google_login
    * You will then be able to get the client ID and client secret.
    * Replace the client_secrets.json with your client secret and also replace the client_id value in login.js.

##### Running the code
`cd` into the project directory and run the below code within the vagrant machine.

Use the below command to setup the database.
```
python database_setup.py
```

To run the item catalog app
```
python application.py
```

You can access the web app via ```localhost:8000```

##### Front-End UI

This project uses [Materialize](https://materializecss.com/) - A modern responsive front-end framework based on Material Design