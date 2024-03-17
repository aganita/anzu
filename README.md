# anzu
![Anzu](anzu.jpg)
Anzû (Mesopotamian Mythology): A demon in the form of a massive bird that guards sacred places. 


Anzu is an IDS to enhance home network security without relying on complex, business-grade firewalls or IDS systems, which are expensive and often excessive for personal use.


### Running locally

Run the following commands to bootstrap your environment if you are unable to run the application using Docker

```bash
pip install -r requirements/dev.txt
npm install
npm run-script build
npm start  # run the webpack dev server and flask server using concurrently
```

Home screen: `http://localhost:5000` 

#### Database Initialization (locally)
Once you have installed your DBMS, run the following to create your app's
database tables and perform the initial migration
```bash
flask db init
flask db migrate
flask db upgrade
```

