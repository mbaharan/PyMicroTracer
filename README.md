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
```ini
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
### Switches
PyMicroTracer can simulate three different scheduling methods: Static, Out-of-order (O3), and Hybrid ((IC)<sup>2</sup>IS). As an example, for following command:
```
./main.py hello_trace.db 100 5,6 ./res/ hello -b 5,6 -s h,o,s -p -d
```
'hello_trace.db' is the run time trace, `100` is the coverage. You can use this value if the `db` file is huge and you want to read a portion of it. The `5,6` is the range of instruction window size which is going to change from `2^5` to `2^6`, `./res/` is the output folder used for saveing results, `-b 5,6` defines the basic block winddow,  `-s h,o,s` defines the scheduling method: `h` for hybrid, `s` for static scheduling and `o` for O3 scheduling. The `-p` will plot the final results, and `-d` will generate the the dependency graph.
## Extracting 'db' file out of your benchmark
---
You can clone 'Tracer' tool from https://github.com/SideChannelMarvels/Tracer to extract instruction db file from your application. If your application is going to leave a long trace of instruction, it is a good idea to modify [Tracer.cpp](https://github.com/SideChannelMarvels/Tracer/blob/master/TracerPIN/Tracer.cpp#L76) and create an index for `bbl_id` in `ins` table.
