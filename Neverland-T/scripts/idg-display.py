#!/usr/bin/python3.7

import __nvld_path__

from nvld.components.idg import IDGenerator


idg = IDGenerator(1, 1)

for _ in range(1000000):
    id_ = idg.gen()
    bin_id = '{0:b}'.format(id_)

    print(f'{bin_id}\t{id_}')
