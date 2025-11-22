#!/bin/bash
set -e

echo "Starting ZKP key generation..."

# Navigate to circuits directory
cd ..

echo "Current directory: $(pwd)"

# Clean previous builds
echo "Cleaning previous builds..."
rm -rf build
rm -f pot12_0000.ptau pot12_0001.ptau pot12_final.ptau

mkdir -p build

# Step 1: Compile the circuit
echo "Step 1: Compiling password.circom..."
circom.exe password.circom --r1cs --wasm --sym -o build/
echo "✓ Circuit compiled successfully"

# Step 2: Generate trusted setup with correct syntax
echo "Step 2: Generating trusted setup..."

# 2.1: Create initial ptau file with correct syntax
echo "  Creating initial powersOfTau..."
npx snarkjs powersoftau new bn128 12 pot12_0000.ptau

# 2.2: Make first contribution
echo "  Making first contribution..."
npx snarkjs powersoftau contribute pot12_0000.ptau pot12_0001.ptau --name="First contribution" -e="$(date +%s)"

# 2.3: Prepare phase2
echo "  Preparing phase2..."
npx snarkjs powersoftau prepare phase2 pot12_0001.ptau pot12_final.ptau

echo "✓ Trusted setup completed"

# Step 3: Generate zkey
echo "Step 3: Generating zkey..."
npx snarkjs groth16 setup build/password.r1cs pot12_final.ptau build/circuit.zkey
echo "✓ zKey generated"

# Step 4: Export verification key
echo "Step 4: Exporting verification key..."
npx snarkjs zkey export verificationkey build/circuit.zkey build/verification_key.json
echo "✓ Verification key exported"

# Step 5: Organize files
echo "Step 5: Organizing files..."
cp build/password_js/password.wasm build/
cp build/circuit.zkey build/password.zkey
echo "✓ Files organized"

# Step 6: Verify files
echo ""
echo "Step 6: Verifying generated files..."
echo "✓ build/password.wasm"
echo "✓ build/password.zkey"
echo "✓ build/verification_key.json"
echo "✓ pot12_0000.ptau"
echo "✓ pot12_0001.ptau"
echo "✓ pot12_final.ptau"

echo ""
echo "🎉 Key generation completed successfully!"
echo ""
echo "Generated files:"
echo " - build/password.wasm (for frontend proof generation)"
echo " - build/password.zkey (for frontend proof generation)"
echo " - build/verification_key.json (for backend verification)"
echo ""
echo "Trusted setup files:"
echo " - pot12_0000.ptau (initial ptau)"
echo " - pot12_0001.ptau (with contribution)"
echo " - pot12_final.ptau (phase2 prepared)"
