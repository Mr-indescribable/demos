#!/usr/bin/python3.6
#coding: utf-8

import json

from .utils.od import ODict
from .utils.misc import VerifiTools
from .exceptions import ConfigError
from .role import Roles


class ConfigLoader():

    @classmethod
    def load_json_file(cls, path):
        try:
            with open(path, 'r') as f:
                content = f.read()
        except FileNotFoundError:
            raise ConfigError(f'Config file not found: {path}')

        content = json.loads(content)
        config = JsonConfig(**content)
        cls.validate_config(config)
        return config

    @classmethod
    def validate_config(cls, config):
        basic = config.basic
        if not VerifiTools.type_matched(basic, ODict):
            raise ConfigError('basic block must be a JSON object')
        if not VerifiTools.type_matched(basic.role, str):
            raise ConfigError('basic.role must be a string')
        if not VerifiTools.type_matched(basic.node_id, int):
            raise ConfigError('basic.node_id must be an integer')
        if not VerifiTools.type_matched(basic.worker_amount, int):
            raise ConfigError('basic.worker_amount must be an integer')
        if not VerifiTools.type_matched(basic.pid_file, str):
            raise ConfigError('basic.pid_file must be a string')

        if basic.role not in Roles._keys():
            raise ConfigError(f'basic.role is invalid')

        net = config.net
        if not VerifiTools.type_matched(basic, ODict):
            raise ConfigError('net block must be a JSON object')
        if not VerifiTools.type_matched(net.identification, str):
            raise ConfigError('net.identification must be a string')
        if not VerifiTools.type_matched(net.aff_listen_addr, str):
            raise ConfigError('net.aff_listen_addr must be a string')
        if not VerifiTools.type_matched(net.aff_listen_port, int):
            raise ConfigError('net.aff_listen_port must be an integer')

        if net.ipv6 is True:
            raise ConfigError('IPv6 is not supported yet.')

        if net.ipv6:
            if not VerifiTools.is_ipv6(net.aff_listen_addr):
                raise ConfigError(
                    'net.aff_listen_addr is not a valid IPv6 address'
                )
        else:
            if not VerifiTools.is_ipv4(net.aff_listen_addr):
                raise ConfigError(
                    'net.aff_listen_addr is not a valid IPv4 address'
                )

        crypto = net.crypto
        if not VerifiTools.type_matched(crypto, ODict):
            raise ConfigError('crypto block must be a JSON object')
        if not VerifiTools.type_matched(crypto.password, str):
            raise ConfigError('crypto.password must be a string')
        if not VerifiTools.type_matched(crypto.cipher, str):
            raise ConfigError('crypto.cipher must be a string')
        if not VerifiTools.type_matched(crypto.salt_len, int):
            raise ConfigError('crypto.salt_len must be an integer')
        if not VerifiTools.type_matched(crypto.iv_len, int):
            raise ConfigError('crypto.iv_len must be an integer')
        if not VerifiTools.type_matched(crypto.iv_duration_range, list):
            raise ConfigError('crypto.iv_duration_range must be an array')

        if len(crypto.iv_duration_range) != 2:
            raise ConfigError('length of crypto.iv_duration_range must be 2')
        if not (
            VerifiTools.type_matched(crypto.iv_duration_range[0], int) and
            VerifiTools.type_matched(crypto.iv_duration_range[1], int)
        ):
            raise ConfigError(
                'crypto.iv_duration_range shall contain integers only'
            )

        shm = config.shm
        if not VerifiTools.type_matched(shm, ODict):
            raise ConfigError('shm block must be a JSON object')
        if not VerifiTools.type_matched(shm.socket_dir, str):
            raise ConfigError('shm.socket_dir must be a string')
        if not VerifiTools.type_matched(shm.manager_socket_name, str):
            raise ConfigError('shm.manager_socket_name must be a string')

        log = config.log
        log_blocks = [log.main, log.shm, log.conn]
        for log_block in log_blocks:
            if not VerifiTools.type_matched(log_block.level, str):
                raise ConfigError('log.*.level must be a string')
            if not VerifiTools.type_matched(log_block.path, str):
                raise ConfigError('log.*.path must be a string')
            if not VerifiTools.type_matched(log_block.stdout, bool):
                raise ConfigError('log.*.stdout must be a boolean')

        if basic.role != Roles.CONTROLLER:
            cluster_entrance = config.cluster_entrance
            if not VerifiTools.type_matched(cluster_entrance, ODict):
                raise ConfigError('cluster_entrance block must be a JSON object')
            if not VerifiTools.type_matched(cluster_entrance.ip, str):
                raise ConfigError('cluster_entrance.ip must be a string')
            if not VerifiTools.type_matched(cluster_entrance.port, int):
                raise ConfigError('cluster_entrance.port must be a integer')

            if net.ipv6:
                if not VerifiTools.is_ipv6(cluster_entrance.ip):
                    raise ConfigError(
                        'cluster_entrance.ip is not a valid IPv6 address'
                    )
            else:
                if not VerifiTools.is_ipv4(cluster_entrance.ip):
                    raise ConfigError(
                        'cluster_entrance.ip is not a valid IPv4 address'
                    )
        else:
            cluster_nodes = config.cluster_nodes
            if not VerifiTools.type_matched(cluster_nodes, ODict):
                raise ConfigError('cluster_nodes block must be a JSON object')

            for node_name, node_info in cluster_nodes:
                if not VerifiTools.type_matched(node_info.ip, str):
                    raise ConfigError(
                        f'cluster_nodes.{node_name}.ip must be a string'
                    )
                if not VerifiTools.type_matched(node_info.role, str):
                    raise ConfigError(
                        f'cluster_nodes.{node_name}.role must be a string'
                    )

                if net.ipv6:
                    if not VerifiTools.is_ipv6(node_info.ip):
                        raise ConfigError(
                            f'cluster_nodes.{node_name}.ip is not a valid '
                            f'IPv6 address'
                        )
                else:
                    if not VerifiTools.is_ipv4(node_info.ip):
                        raise ConfigError(
                            f'cluster_nodes.{node_name}.ip is not a valid '
                            f'IPv4 address'
                        )

                if node_info.role not in Roles._keys():
                    raise ConfigError(
                        f'cluster_nodes.{node_name}.role is invalid'
                    )


class JsonConfig(ODict):

    ''' The entity of configuration in json format
    '''
