# FreeRDP patches to enable the honey pot

These patches add the logging functionality required in order for us to crack the supplied credentials.

## Apply the patch
~~~sh
git apply --ignore-space-change --ignore-whitespace x.y.n.patch
~~~

## Build
~~~sh
mkdir build
cd build
cmake -DWITH_SERVER=ON ..
cmake --build .
~~~

## Generate a SAM file
~~~sh
./winpr/tools/hash-cli/winpr-hash -u ollie -p yoink -f sam > sam
~~~

## Running the X Server
~~~sh
Xvfb :0 -screen 1 1024x768x24
~~~~

## Run the RDP Enabled FreeRDP Server
~~~sh
./server/shadow/freerdp-shadow-cli /sec:nla /sam-file:sam
~~~
