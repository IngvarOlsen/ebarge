# eBarge
School iot project

## Linux setup

### 1. Run update and upgrade and install git
```
sudo apt update
sudo apt upgrade
sudo apt-get install git
```

### 2. Download files via github
```
git clone https://github.com/IngvarOlsen/weGrain.git
```

### 3. Make virtual enviroment inside the gitfolder, or copy the folders "template", "static" and app.py to your new enviroment
```
pip install virtualenv
mkdir weGrain
cd weGrain
virtualenv venv
venv/bin/activate
```

### 4. Once activated install Flask
```
pip install Flask
```

### 5. Install rest of dependencies 
```
sudo apt install sqlite3
pip install flask_login

```



