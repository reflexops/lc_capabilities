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

from beach.actor import Actor
import re
import base64
_xm_ = Actor.importLib( 'utils/hcp_helpers', '_xm_' )

class WinSuspCmdLine ( object ):
    def __init__( self, fromActor ):
        self.b64re = re.compile( '([A-Za-z0-9+/]{20,})' )
        self.scmd = { 'rtlo' : re.compile( r'.*\xE2\x80\x8F.*' ),}

    def analyze( self, event, sensor, *args ):
        if not sensor.aid.isWindows():
            return False

        if event.dataType not in ( 'notification.NEW_PROCESS', 
                                   'notification.EXISTING_PROCESS' ):
            return False

        isSusp = False

        for cmdLine in _xm_( event.data, '?/base.COMMAND_LINE' ):
            # Look for ^ carrets as they can be used to mask intent
            if 3 <= cmdLine.count( '^' ):
                return True

            for possibleB64 in self.b64re.findall( cmdLine ):
                try:
                    base64.b64decode( token )
                    return True
                except:
                    pass

            for k, v in self.scmd.iteritems():
                if v.match( cmdLine ):
                    return True
        return False