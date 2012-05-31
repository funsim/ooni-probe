"""
This test performs a traceroute using multiple protocols.
"""
from zope.interface import implements
from twisted.python import usage
from twisted.plugin import IPlugin
from plugoo.tests import ITest, OONITest

class MultiProtocolTracerouteArgs(usage.Options):
    optParameters = [['asset', 'a', None, 'Asset file'],
                     ['resume', 'r', 0, 'Resume at this index']]

class MultiProtocolTracerouteTest(OONITest):
    implements(IPlugin, ITest)

    shortName = "MPT"
    description = "MultiProtocolTraceroute"
    requirements = None
    options = MultiProtocolTracerouteArgs
    blocking = True

    def control(self, experiment_result, args):
        # What you return here ends up inside of the report.
        return {}

    def experiment(self, args):
        # What you return here gets handed as input to control
        return {}

    def load_assets(self):
        if self.local_options:
            return {'asset': Asset(self.local_options['asset'])}
        else:
            return {}

# We need to instantiate it otherwise getPlugins does not detect it
# XXX Find a way to load plugins without instantiating them.
MPT = MultiProtocolTracerouteTest(None, None, None)
