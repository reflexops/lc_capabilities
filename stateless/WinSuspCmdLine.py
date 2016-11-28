# Copyright 2015 refractionPOINT
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
    "description" : "Detects execution from suspicious command lines of Windows.",
    "requirements" : "",
    "feeds" : [ "notification.NEW_PROCESS" ],
    "platform" : "windows",
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
import base64
ObjectTypes = Actor.importLib( 'utils/ObjectsDb', 'ObjectTypes' )
StatelessActor = Actor.importLib( 'Detects', 'StatelessActor' )
_xm_ = Actor.importLib( 'utils/hcp_helpers', '_xm_' )

class WinSuspCmdLine ( StatelessActor ):
    def init( self, parameters, resources ):
        super( WinSuspCmdLine, self ).init( parameters, resources )
        self.b64re = re.compile( '([A-Za-z0-9+/]{3,})' )
        self.scmd = { 'rtlo' : re.compile( r'.*\xE2\x80\x8F.*' ),}

    def process( self, detects, msg ):
        routing, event, mtd = msg.data
        isSusp = False

        for cmdLine in _xm_( event, '?/base.COMMAND_LINE' ):
            # Look for ^ carrets as they can be used to mask intent
            if 3 <= cmdLine.count( '^' ):
                isSusp = True
                break

            for possibleB64 in self.b64re.findall( cmdLine ):
                if 20 <= len( possibleB64 ):
                    try:
                        base64.b64decode( token )
                        isSusp = True
                        break
                    except:
                        pass

            if isSusp: break

            for k, v in self.scmd.iteritems():
                if v.match( cmdLine ):
                    isSusp = True
                    break

            if isSusp: break

        if isSusp:
            detects.add( 70, 
                         'binary executing with a suspicious command line',
                         event )
