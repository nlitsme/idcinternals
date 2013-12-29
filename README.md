ABOUT

this is a small plugin i made for IDA ( http://www.hex-rays.com/ )

it attempts to investigate the internals of IDA.
by dumping the RootNode.
and IDCFuncs

It can disassemble the internal bytecode representation of IDC scripts.
dbdump knows how to find the idc compiled code for several ida
versions, but possibly not for all.

HOW TO USE

* install
* startup ida
* type alt-2
* read the 'dump_db.log' file in the directory from where ida was started.


BUILD REMARKS


This is known to build on OSX 10.9, the windows build has not been tested for quite a while.

The boost library headers are expected in /opt/local/include

No attempt has been made to make this very portable.


INSTALLATION

* type make
* type make install


AUTHOR

Willem Hengeveld
itsme@xs4all.nl

