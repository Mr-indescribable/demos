#!/usr/bin/python3.6
#coding: utf-8


'''
Neverland 私有 TCP Over UDP 协议（NLTOU）初稿

计划中， NLTOU 的主要特性有以下几项：

    1、由集群出入口节点完成 TCP 与 UDP 的转换：
        一个简陋的 Mind Map:

            +--------+   TCP   +----------+   UDP   +--------+   TCP   +------+
            |        | ------> | cluster  | ------> |        | ------> |      |
            | client |         | entrance |         | outlet |         | dest |
            |        | <------ | (relay)  | <------ |        | <------ |      |
            +--------+   TCP   +----------+   UDP   +--------+   TCP   +------+

    2、信道：
        每个 TCP 连接都被认为是一个 UDP Channel，所有 NLTOU 的 UDP 报文都需要携带
        Channel 信息，entrance 和 outlet 节点将根据这个 Channel 信息来决定该 UDP
        报文将被输入到哪个 TCP 流中。

    3、独立的 Worker 和端口：
        当开启 NLTOU 支持之后，entrance 以及 outlet 将会启动独立的 Worker 来
        监听 2 个专供 NLTOU 使用的端口，TCP 和 UDP 各一个。

    4、非同步认证：
        在 client 与 entrance 建立 TCP 连接之前，client 应当先完成认证。
        此认证过程发生通过常规的 Neverland 通信协议完成，在完成认证之后，
        client 的信息将会被 entrance 记录在共享内存中，并由 TOU Worker
        在 accept TCP 连接时读取。
'''


if __name__ == '__main__':
    print(__doc__)
