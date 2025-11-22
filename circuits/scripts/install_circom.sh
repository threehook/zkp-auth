curl -L -o circom.exe https://github.com/iden3/circom/releases/latest/download/circom-windows-amd64.exe

# Make it executable
chmod +x circom.exe

# Move to a directory in your PATH
mv circom.exe /usr/bin/circom.exe

# Test it
circom.exe --version
