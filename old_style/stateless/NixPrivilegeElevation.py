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
    "type" : "stateless",
    "description" : "Detects a privilege elevation on a Nix system.",
    "requirements" : "",
    "feeds" : [ "notification.NEW_PROCESS" ],
    "platform" : [ "osx", "linux" ],
    "author" : "maximelb@google.com",
    "version" : "1.0",
    "scaling_factor" : 1000,
    "n_concurrent" : 5,
    "usage" : {}
}
LC_DETECTION_MTD_END
'''
###############################################################################

from beach.actor import Actor
import re
ObjectTypes = Actor.importLib( 'utils/ObjectsDb', 'ObjectTypes' )
StatelessActor = Actor.importLib( 'Detects', 'StatelessActor' )
_x_ = Actor.importLib( 'utils/hcp_helpers', '_x_' )

class NixPrivilegeElevation ( StatelessActor ):
    def init( self, parameters, resources ):
        super( NixPrivilegeElevation, self ).init( parameters, resources )

    def process( self, detects, msg ):
        routing, event, mtd = msg.data
        
        procUid = _x_( event, '?/base.USER_ID' )
        procPath = _x_( event, '?/base.FILE_PATH' )
        if procUid is not None and 0 == procUid and procPath is not None and not procPath.lower().endswith( 'sudo' ):
            parentUid = _x_( event, '?/base.PARENT/base.USER_ID' )
            if parentUid is not None and 0 != parentUid:
                detects.add( 90, 
                             'an unprivileged process spawned a high privilege process', 
                             event )
