# Apply the patch
git apply --ignore-space-change --ignore-whitespace x.y.n.patch

# Build
mkdir build
cd build
cmake -DWITH_SERVER=ON ..
cmake --build .

# Generate a SAM file
./winpr/tools/hash-cli/winpr-hash -u ollie -p yoink -f sam > sam

# Running the X Server
Xvfb :0 -screen 1 1024x768x24

# Run the RDP Enabled FreeRDP Server
./server/shadow/freerdp-shadow-cli /sec:nla /sam-file:sam
