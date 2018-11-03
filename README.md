# PyMicroTracer
This is a trace-based micro-architecture simulator. This framework is able to approximate  both static, dynamic ILPs at this phase.

## Installation
---
Clone Capstone dissambler tools and and branch it to next and install its python bindings:
```sh
git clone https://github.com/aquynh/capstone.git
cd capstone
git branch next
./make.sh
sudo ./make.sh install
cd bindings/python/
sudo python3 setup.py install
```

Install following Ubuntu packages:
```sh
sudo apt-get install python3-tk unixodbc unixodbc-dev unixodbc-bin unixodbc libsqlite3-dev
```
Next install following python modules:
```sh
sudo pip3 install networkx numpy matplotlib pyodbc pydot colour xdot
```
Download odbc driver `sqliteodbc-0.9995.tar.gz` from http://www.ch-werner.de/sqliteodbc/ and install it:
```sh
tar xvf sqliteodbc-0.9995.tar.gz
./configure && make && sudo make install
```

Cerate odbc configuration file:
`
sudo nano /etc/odbcinst.ini
`
And copy following content to `odbcinst.ini`
```
[SQLite3]
Description=SQLite ODBC Driver
Driver=/usr/local/lib/libsqlite3odbc.so
Setup=/usr/local/lib/libsqlite3odbc.so
Threading=2

[SQLite]
Description=SQLite ODBC Driver
Driver=/usr/local/lib/libsqliteodbc.so
Setup=/usr/local/lib/libsqliteodbc.so
Threading=2
```
## Usage
---
Please refer to example file and execute the `runme.sh` file
```sh
./runme.sh
```
All the generated graph and result will be saved in `./res` folder
### Extracting 'db' file out of your application
---
You can clone 'Tracer' tool from https://github.com/SideChannelMarvels/Tracer to extract instauction db file from your application.
