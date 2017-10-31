# Copyright 2017 Google, Inc
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

###############################################################################
# Metadata
'''
LC_DETECTION_MTD_START
{
    "type" : "stateful",
    "description" : "Detects a privilege elevation on a Nix system.",
    "requirements" : "",
    "feeds" : [],
    "platform" : [ "osx", "linux" ],
    "author" : "maximelb@google.com",
    "version" : "1.0",
    "scaling_factor" : 500,
    "n_concurrent" : 5,
    "usage" : {}
}
LC_DETECTION_MTD_END
'''
###############################################################################

from beach.actor import Actor
import re
ProcessDescendant = Actor.importLib( 'analytics/StateAnalysis/descriptors', 'ProcessDescendant' )
StatefulActor = Actor.importLib( 'Detects', 'StatefulActor' )

class NixPrivilegeElevation ( StatefulActor ):
    def initMachines( self, parameters ):
        self.shardingKey = 'agentid'
        
        privEsc = ProcessDescendant( name = 'nix_privilege_elevation',
                                     priority = 90,
                                     summary = 'An unprivileged process spawned a high privilege process.',
                                     isParentRoot = False,
                                     isDirectOnly = True,
                                     isChildRoot = True,
                                     childRegExp = re.compile( r'.*(/|\\)((?!sudo))$' ) )

        self.addStateMachineDescriptor( privEsc )