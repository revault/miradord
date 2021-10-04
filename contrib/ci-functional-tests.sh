set -xe

# Do the linter check early for quicker feedback
pip install black
black --check tests/

# Build the miradord binary
cargo build --release

# Download the bitcoind binary
BITCOIND_VERSION="22.0"
DIR_NAME="bitcoin-$BITCOIND_VERSION"
ARCHIVE_NAME="$DIR_NAME.tar.gz"
curl https://bitcoincore.org/bin/bitcoin-core-$BITCOIND_VERSION/bitcoin-$BITCOIND_VERSION-x86_64-linux-gnu.tar.gz -o $ARCHIVE_NAME
tar -xzf $ARCHIVE_NAME
sudo mv $DIR_NAME/bin/bitcoind /usr/local/bin/

# Run the functional tests
python3 -m venv venv
. venv/bin/activate
pip install -r tests/requirements.txt
VERBOSE=1 LOG_LEVEL=debug TIMEOUT=60 pytest -n2 -vvv --log-cli-level=DEBUG tests/
