# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
import unittest
from io import StringIO
from unittest.mock import Mock, PropertyMock, patch

import yaml
from ops import testing
from ops.model import ActiveStatus, BlockedStatus, WaitingStatus

from charm import BASE_CONFIG_PATH, CONFIG_FILE_NAME, NRF_RELATION_NAME, UDMOperatorCharm

logger = logging.getLogger(__name__)

VALID_NRF_URL = "https://nrf:443"
EXPECTED_CONFIG_FILE_PATH = "tests/unit/expected_udmcfg.yaml"


class TestCharm(unittest.TestCase):
    @patch(
        "charm.KubernetesServicePatch",
        lambda charm, ports: None,
    )
    def setUp(self):
        self.maxDiff = None
        self.namespace = "whatever"
        self.default_database_application_name = "mongodb-k8s"
        self.metadata = self._get_metadata()
        self.container_name = list(self.metadata["containers"].keys())[0]
        self.harness = testing.Harness(UDMOperatorCharm)
        self.harness.set_model_name(name=self.namespace)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    def _get_metadata(self) -> dict:
        """Reads `metadata.yaml` and returns it as a dictionary.

        Returns:
            dics: metadata.yaml as a dictionary.
        """
        with open("metadata.yaml", "r") as f:
            data = yaml.safe_load(f)
        return data

    def _read_file(self, path: str) -> str:
        """Reads a file an returns as a string.

        Args:
            path (str): path to the file.

        Returns:
            str: content of the file.
        """
        with open(path, "r") as f:
            content = f.read()
        return content

    def _create_nrf_relation(self) -> int:
        """Creates NRF relation.

        Returns:
            int: relation id.
        """
        relation_id = self.harness.add_relation(
            relation_name=NRF_RELATION_NAME, remote_app="nrf-operator"
        )
        self.harness.add_relation_unit(relation_id=relation_id, remote_unit_name="nrf-operator/0")
        return relation_id

    def test_given_container_cant_connect_when_configure_sdcore_udm_then_status_is_waiting(  # noqa: E501
        self,
    ):
        self.harness.set_can_connect(container=self.container_name, val=False)

        self.harness.charm._configure_sdcore_udm(event=Mock())

        self.assertEqual(
            self.harness.model.unit.status, WaitingStatus("Waiting for container to be ready")
        )

    def test_given_container_can_connect_and_fiveg_nrf_relation_is_not_created_when_configure_sdcore_udm_then_status_is_blocked(  # noqa: E501
        self,
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)

        self.harness.charm._configure_sdcore_udm(event=Mock())

        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus("Waiting for `fiveg_nrf` relation to be created"),
        )

    def test_given_container_can_connect_and_fiveg_nrf_relation_is_created_and_not_available_when_configure_sdcore_udm_then_status_is_waiting(  # noqa: E501
        self,
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        self._create_nrf_relation()

        self.harness.charm._configure_sdcore_udm(event=Mock())

        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting for NRF endpoint to be available"),
        )

    @patch("charms.sdcore_nrf.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    def test_given_container_storage_is_not_attached_when_configure_sdcore_udm_then_status_is_waiting(  # noqa: E501
        self, patched_nrf_url
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        patched_nrf_url.return_value = VALID_NRF_URL
        self._create_nrf_relation()
        self.harness.charm._storage_is_attached = Mock(return_value=False)

        self.harness.charm._configure_sdcore_udm(event=Mock())

        self.assertEqual(
            self.harness.model.unit.status, WaitingStatus("Waiting for the storage to be attached")
        )

    @patch("charm.check_output")
    @patch("ops.model.Container.pull")
    @patch("ops.model.Container.exists")
    @patch("ops.Container.push")
    @patch("charms.sdcore_nrf.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    def test_given_config_file_is_not_written_when_configure_sdcore_udm_is_called_then_config_file_is_written_with_expected_content(  # noqa: E501
        self, patched_nrf_url, patch_push, patch_exists, patch_pull, patch_check_output
    ):
        pod_ip = "1.1.1.1"
        patch_check_output.return_value = pod_ip.encode()
        self.harness.set_can_connect(container=self.container_name, val=True)
        patched_nrf_url.return_value = VALID_NRF_URL
        self._create_nrf_relation()
        patch_exists.return_value = [True, False]
        expected_config_file_content = self._read_file(EXPECTED_CONFIG_FILE_PATH)

        self.harness.charm._configure_sdcore_udm(event=Mock())

        patch_push.assert_called_with(
            path=f"{BASE_CONFIG_PATH}/{CONFIG_FILE_NAME}",
            source=expected_config_file_content.strip(),
        )

    @patch("charm.check_output")
    @patch("ops.model.Container.pull")
    @patch("ops.model.Container.exists")
    @patch("ops.Container.push")
    @patch("charms.sdcore_nrf.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    def test_given_config_file_is_written_and_is_not_changed_when_configure_sdcore_udm_is_called_then_config_file_is_not_written(  # noqa: E501
        self, patched_nrf_url, patch_push, patch_exists, patch_pull, patch_check_output
    ):
        pod_ip = "1.1.1.1"
        patch_check_output.return_value = pod_ip.encode()
        patch_pull.return_value = StringIO(self._read_file(EXPECTED_CONFIG_FILE_PATH))
        self.harness.set_can_connect(container=self.container_name, val=True)
        patched_nrf_url.return_value = VALID_NRF_URL
        self._create_nrf_relation()
        self.harness.charm._storage_is_attached = Mock(return_value=True)
        patch_exists.return_value = [True, True]

        self.harness.charm._configure_sdcore_udm(event=Mock())

        patch_push.assert_not_called()

    @patch("ops.model.Container.restart")
    @patch("charm.check_output")
    @patch("ops.model.Container.pull")
    @patch("ops.model.Container.exists")
    @patch("ops.Container.push")
    @patch("charms.sdcore_nrf.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    def test_given_config_file_is_written_and_is_not_changed_when_configure_sdcore_udm_is_called_then_after_writting_config_file_service_is_not_restarted(  # noqa: E501
        self,
        patched_nrf_url,
        patch_push,
        patch_exists,
        patch_pull,
        patch_check_output,
        patch_restart,
    ):
        pod_ip = "1.1.1.1"
        patch_check_output.return_value = pod_ip.encode()
        patch_pull.return_value = StringIO(self._read_file(EXPECTED_CONFIG_FILE_PATH))
        self.harness.set_can_connect(container=self.container_name, val=True)
        patched_nrf_url.return_value = VALID_NRF_URL
        self._create_nrf_relation()
        self.harness.charm._storage_is_attached = Mock(return_value=True)
        patch_exists.return_value = [True, True]

        self.harness.charm._configure_sdcore_udm(event=Mock())

        patch_restart.assert_not_called()

    @patch("charm.check_output")
    @patch("ops.model.Container.pull")
    @patch("ops.model.Container.exists")
    @patch("ops.Container.push")
    @patch("charms.sdcore_nrf.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    def test_given_config_file_is_written_and_is_changed_when_configure_sdcore_udm_is_called_then_config_file_is_written(  # noqa: E501
        self, patched_nrf_url, patch_push, patch_exists, patch_pull, patch_check_output
    ):
        pod_ip = "1.1.1.1"
        patch_check_output.return_value = pod_ip.encode()
        patch_pull.return_value = StringIO("super different config file content")
        self.harness.set_can_connect(container=self.container_name, val=True)
        patched_nrf_url.return_value = VALID_NRF_URL
        self._create_nrf_relation()
        self.harness.charm._storage_is_attached = Mock(return_value=True)
        patch_exists.return_value = [True, True]
        expected_config_file_content = self._read_file(EXPECTED_CONFIG_FILE_PATH)

        self.harness.charm._configure_sdcore_udm(event=Mock())

        patch_push.assert_called_with(
            path=f"{BASE_CONFIG_PATH}/{CONFIG_FILE_NAME}",
            source=expected_config_file_content.strip(),
        )

    @patch("ops.model.Container.restart")
    @patch("charm.check_output")
    @patch("ops.model.Container.pull")
    @patch("ops.model.Container.exists")
    @patch("ops.Container.push")
    @patch("charms.sdcore_nrf.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    def test_given_config_file_is_written_and_is_changed_when_configure_sdcore_udm_is_called_then_after_writting_config_file_service_is_restarted(  # noqa: E501
        self,
        patched_nrf_url,
        patch_push,
        patch_exists,
        patch_pull,
        patch_check_output,
        patch_container_restart,
    ):
        pod_ip = "1.1.1.1"
        patch_check_output.return_value = pod_ip.encode()
        patch_pull.return_value = StringIO("super different config file content")
        self.harness.set_can_connect(container=self.container_name, val=True)
        patched_nrf_url.return_value = VALID_NRF_URL
        self._create_nrf_relation()
        self.harness.charm._storage_is_attached = Mock(return_value=True)
        patch_exists.return_value = [True, True]

        self.harness.charm._configure_sdcore_udm(event=Mock())

        patch_container_restart.assert_called_with(self.container_name)

    @patch("ops.model.Container.restart")
    @patch("charm.check_output")
    @patch("ops.model.Container.pull")
    @patch("ops.model.Container.exists")
    @patch("ops.Container.push")
    @patch("charms.sdcore_nrf.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    def test_given_config_file_is_written_when_configure_sdcore_udm_is_called_then_status_is_active(  # noqa: E501
        self,
        patched_nrf_url,
        patch_push,
        patch_exists,
        patch_pull,
        patch_check_output,
        patch_container_restart,
    ):
        pod_ip = "1.1.1.1"
        patch_check_output.return_value = pod_ip.encode()
        patch_pull.return_value = StringIO("super different config file content")
        self.harness.set_can_connect(container=self.container_name, val=True)
        patched_nrf_url.return_value = VALID_NRF_URL
        self._create_nrf_relation()
        self.harness.charm._storage_is_attached = Mock(return_value=True)
        patch_exists.return_value = [True, False]

        self.harness.charm._configure_sdcore_udm(event=Mock())

        self.assertEqual(self.harness.model.unit.status, ActiveStatus())
