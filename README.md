ABOUT
=====

This is a small plugin i made for IDA Pro ( http://www.hex-rays.com/ )

It attempts to investigate the internals of IDA.
For older versions of IDA it could dump the internal netnode
representation of the `.idb` file. This no longer works.
What does work:
* print a list of all builtin IDC functions by enumerating `IDCFuncs`
* disassemble all compiled IDC functions by locating the internal pointer
   to the compiled functions list.

dbdump knows how to find the idc compiled bytecode for several ida
versions, but possibly not for all.

HOW TO USE
=====

* install
* startup ida
* type alt-2
* read the `dump_db.log` file in the directory from where ida was started.


BUILD REMARKS
=====


* This is known to build on OSX 10.9 - 10.12, the windows build has not been tested for quite a while.
* The boost library headers are expected in /opt/local/include
* No attempt has been made to make this very portable.


INSTALLATION
=====

* type make
* type make install


AUTHOR
=====

(C) 2003-2017 Willem Hengeveld <itsme@xs4all.nl>

