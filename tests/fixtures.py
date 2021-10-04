from concurrent import futures
from ephemeral_port_reserve import reserve
from test_framework.bitcoind import Bitcoind
from test_framework.miradord import Miradord
from test_framework.utils import (
    get_descriptors,
    EXECUTOR_WORKERS,
    STKS_XPRIVS,
    STKS_XPUBS,
)

import bip32
import logging
import os
import pytest
import shutil
import tempfile
import time

__attempts = {}


@pytest.fixture(scope="session")
def test_base_dir():
    d = os.getenv("TEST_DIR", "/tmp")

    directory = tempfile.mkdtemp(prefix="miradord-tests-", dir=d)
    print("Running tests in {}".format(directory))

    yield directory

    content = os.listdir(directory)
    if content == []:
        shutil.rmtree(directory)
    else:
        print(f"Leaving base dir '{directory}' as it still contains {content}")


# Taken from https://docs.pytest.org/en/latest/example/simple.html#making-test-result-information-available-in-fixtures
@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    # execute all other hooks to obtain the report object
    outcome = yield
    rep = outcome.get_result()

    # set a report attribute for each phase of a call, which can
    # be "setup", "call", "teardown"

    setattr(item, "rep_" + rep.when, rep)


@pytest.fixture
def directory(request, test_base_dir, test_name):
    """Return a per-test specific directory.

    This makes a unique test-directory even if a test is rerun multiple times.

    """
    global __attempts
    # Auto set value if it isn't in the dict yet
    __attempts[test_name] = __attempts.get(test_name, 0) + 1
    directory = os.path.join(
        test_base_dir, "{}_{}".format(test_name, __attempts[test_name])
    )

    if not os.path.exists(directory):
        os.makedirs(directory)

    yield directory

    # test_base_dir is at the session scope, so we can't use request.node as mentioned in
    # the doc linked in the hook above.
    if request.session.testsfailed == 0:
        try:
            shutil.rmtree(directory)
        except Exception:
            files = [
                os.path.join(dp, f) for dp, _, fn in os.walk(directory) for f in fn
            ]
            print("Directory still contains files:", files)
            raise
    else:
        print(f"Test failed, leaving directory '{directory}' intact")


@pytest.fixture
def test_name(request):
    yield request.function.__name__


@pytest.fixture
def executor(test_name):
    ex = futures.ThreadPoolExecutor(
        max_workers=EXECUTOR_WORKERS, thread_name_prefix=test_name
    )
    yield ex
    ex.shutdown(wait=False)


@pytest.fixture
def bitcoind(directory):
    bitcoind = Bitcoind(bitcoin_dir=directory)
    bitcoind.startup()

    bitcoind.rpc.createwallet(bitcoind.rpc.wallet_name, False, False, "", False, True)

    while bitcoind.rpc.getbalance() < 50:
        bitcoind.rpc.generatetoaddress(1, bitcoind.rpc.getnewaddress())

    while bitcoind.rpc.getblockcount() <= 1:
        time.sleep(0.1)

    yield bitcoind

    bitcoind.cleanup()


@pytest.fixture
def miradord(bitcoind, directory):
    datadir = os.path.join(directory, "miradord")
    os.makedirs(datadir, exist_ok=True)

    # We only care about the stakeholders, so we use dummy keys for the others.
    cpfp_xpubs = [
        "xpub6FD2XRGE3DAJzb69LXMEAiHfj3U4xVqLExMSV4DJXs5zCntHmtdvpkErLwAMGMnKJN2m3LGgaaAMvBELwNNJDAwWvidNMxVgSqLyoC2y2Kc"
    ]
    cosigs_keys = [
        "03170fcc522ee69d743c15e40379fcabb6c607ff3dbeb68cbdd6da5da9c9d048a5",
        "03b8789ff36bf55a77a20af0a0b1668d8dd3df2e7b7f81da058b5236f0120aba38",
        "028d5f3bb2bcf819f785086e0b04833361f773a328aeff41ea5dd248fe03d18b25",
        "03c977891e952393a742f9f2ef5cd4cefb7cbe58d9b3acfdc750b38f6931764ba8",
    ]
    mans_xpubs = [
        "xpub6CFH8m3bnUFXvS78XZyCQ9mCbp7XmKXbS67YHGUS3NxHSLhAMCGHGaEPojcoYt5PYnocyuScAM5xuDzf4BqFQt3fhmKEaRgmVzDcAR46Byh",
        "xpub6ECZqYNQzHkveSWmsGh6XSL8wMGXRtoZ5hkbWXwRSVEyEsKADe34dbdnMob1ZjUpd4TD7no1isnnvpQq9DchFes5DnHJ7JupSntZsKr7VbQ",
    ]
    (dep_desc, unv_desc, cpfp_desc) = get_descriptors(
        STKS_XPUBS, cosigs_keys, mans_xpubs, len(mans_xpubs), cpfp_xpubs, 232
    )
    emer_addr = "bcrt1qewc2348370pgw8kjz8gy09z8xyh0d9fxde6nzamd3txc9gkmjqmq8m4cdq"

    coordinator_noise_key = (
        "d91563973102454a7830137e92d0548bc83b4ea2799f1df04622ca1307381402"
    )
    miradord = Miradord(
        datadir,
        dep_desc,
        unv_desc,
        cpfp_desc,
        emer_addr,
        reserve(),
        os.urandom(32),
        os.urandom(32),
        coordinator_noise_key,  # Unused yet
        reserve(),  # Unused yet
        bitcoind,
    )
    miradord.start()

    yield miradord

    miradord.cleanup()
