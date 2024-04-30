# anzu
## Description
![Anzu](anzu.jpg)
Anzû (Mesopotamian Mythology): A demon in the form of a massive bird that guards sacred places. 


Anzu is an IDS to enhance home network security without relying on complex, business-grade firewalls or IDS systems, which are expensive and often excessive for personal use.

## Stack
- [Node](https://nodejs.org) `22.0.0` or newer
- [Python](https://www.python.org) `3.12.2` or newer

## Run locally
1. Install Javascript dependencies
``` shell
$ npm install
```
2. Create and activate Python virtual environment
```shell
$ python -m venv myenv
$ source myenv/bin/activate
```
3. Install Python dependencies
```shell
pip install -r requirements/dev.txt
```
4. Build packages
```shell
$ sudo npm run-script build
```
5. Initialize the database
```shell
$ sudo flask db init
$ sudo flask db migrate
$ sudo flask db upgrade
```
6. Run the application.
```shell
$ sudo npm start  
```
Home screen: `http://localhost:5000` 


