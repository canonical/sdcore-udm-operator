#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.


import logging
from pathlib import Path

import pytest
import yaml

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./metadata.yaml").read_text())
APPLICATION_NAME = METADATA["name"]
NRF_APP_NAME = "sdcore-nrf"
DATABASE_APP_NAME = "mongodb-k8s"


async def _deploy_database(ops_test):
    """Deploy a MongoDB."""
    await ops_test.model.deploy(
        DATABASE_APP_NAME,
        application_name=DATABASE_APP_NAME,
        channel="5/edge",
        trust=True,
    )


async def _deploy_nrf(ops_test):
    """Deploy a NRF."""
    await ops_test.model.deploy(
        NRF_APP_NAME,
        application_name=NRF_APP_NAME,
        channel="edge",
        trust=True,
    )


@pytest.fixture(scope="module")
@pytest.mark.abort_on_fail
async def build_and_deploy(ops_test):
    """Build the charm-under-test and deploy it."""
    charm = await ops_test.build_charm(".")
    resources = {
        "udm-image": METADATA["resources"]["udm-image"]["upstream-source"],
    }
    await ops_test.model.deploy(
        charm,
        resources=resources,
        application_name=APPLICATION_NAME,
        trust=True,
    )
    await _deploy_database(ops_test)
    await _deploy_nrf(ops_test)


@pytest.mark.abort_on_fail
async def test_given_charm_is_built_when_deployed_then_status_is_blocked(
    ops_test,
    build_and_deploy,
):
    await ops_test.model.wait_for_idle(
        apps=[APPLICATION_NAME],
        status="blocked",
        timeout=1000,
    )


@pytest.mark.abort_on_fail
async def test_relate_and_wait_for_active_status(
    ops_test,
    build_and_deploy,
):
    await ops_test.model.add_relation(relation1=NRF_APP_NAME, relation2=DATABASE_APP_NAME)

    await ops_test.model.add_relation(
        relation1=f"{APPLICATION_NAME}:fiveg_nrf", relation2=NRF_APP_NAME
    )

    await ops_test.model.wait_for_idle(
        apps=[APPLICATION_NAME],
        status="active",
        timeout=1000,
    )
