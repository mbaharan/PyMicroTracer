# PyMicroTracer
This is a trace-based micro-architecture simulator. This framework is able to approximate 
both static, dynamic ILPs at this phase. This is the continues work, so please be ready for more updated :)

You can test application by following code:
`./main.py ./example/arch/arm/hello_trace.db 100 5,6 ./example/arch/arm/res/ hello`

This framework needs some other open-source tools to be installed. I am going to create a wiki page
how to install them. 



sudo pip3 install networkx
sudo pip3 install numpy
sudo pip3 install matplotlib
sudo pip3 install pyodbc

sudo apt-get install python3-tk
sudo apt-get install unixodbc unixodbc-dev
sudo apt-get install unixodbc-dev unixodbc-bin unixodbc
sudo apt-get install libsqlite3-dev

wget http://www.ch-werner.de/sqliteodbc/sqliteodbc-0.9995.tar.gz
tar xvf sqliteodbc-0.9995.tar.gz
./configure && make && make install
sudo nano /etc/odbcinst.ini
---
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
---
