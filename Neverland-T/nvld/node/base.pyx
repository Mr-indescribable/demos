import logging


logger = logging.getLogger('Node')


class BaseNode():

    def __init__(self, config):
        self.config = config

    def load_glb_moduls(self):
        pass

    def main(self):
        pass
