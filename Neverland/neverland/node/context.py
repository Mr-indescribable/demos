#!/usr/bin/python3.6
#coding: utf-8


class NodeContext():

    ''' Node context container

    The global context container.
    '''

    # pid of the master process
    master_pid = None

    # pid of current process
    pid = None

    # pid of the packet repeater worker process
    pkt_rpter_pid = None

    # the IP address that the service is listening
    local_ip = None

    # the port that the service is listening
    listen_port = None

    # the IDGenerator instance
    id_generator = None

    # The core instance
    core = None

    # The first instance of efferents that generated by the node
    main_efferent = None

    # the protocol wrapper instance generated by the node
    protocol_wrapper = None

    # The packet manager instance
    pkt_mgr = None

    # The connection manager instance
    conn_mgr = None

    # The cryptor_stash is used to store cryptors of managed connections.
    # The entity of a connection only contains the necessary information
    # of the connection, so that all worker processes could share it.
    #
    # And for using the connection, we need to instantiate a Cryptor for
    # the connection. And then, this cryptor object will stored here. It will
    # be a part of the connection, once the connection has been removed, it
    # shall be removed too.
    #
    # Here is the inner data structure if cryptor_stash:
    #
    #     {
    #         "default_cryptor": the cryptor with the default iv,
    #
    #         "remote_ip_0:port": {
    #             "main_cryptor": main_cryptor,
    #             "fallback_cryptor": fallback_cryptor,
    #         }
    #
    #         "remote_ip_1:port": {
    #             "main_cryptor": main_cryptor,
    #             "fallback_cryptor": fallback_cryptor,
    #         }
    #     }
    #
    # We will keep 2 connections for each remote node in connection management.
    # And here, we shall keep 2 cryptors for each remote node as well. And we
    # name the cryptor object belongs to the connection in Slot-1 as
    # "main cryptor" and the cryptor object belongs to the connection
    # in Slot-0 as "fallback cryptor".
    #
    # The Cryptor with the default iv is provided as well, but it does not
    # belong to any connection and only used on CONN_CTRL packets.
    cryptor_stash = dict()

    # The last udpate time of Cryptor instances in cryptor_stash.
    # Has the same data structure as the cryptor_stash (without default_cryptor).
    cryptor_update_time = dict()
