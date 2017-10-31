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
_x_ = Actor.importLib( 'utils/hcp_helpers', '_x_' )

class ShadowVolumeTampering ( object ):
    def __init__( self ):
        self.vssadmin = re.compile( r'.*vssadmin\.exe', re.IGNORECASE )
        self.vssadminCommands = re.compile( r'.*(delete shadows)|(resize shadowstorage)', re.IGNORECASE )
        self.wmic = re.compile( r'.*wmic\.exe', re.IGNORECASE )
        self.wmicCommands = re.compile( r'.*(shadowcopy delete)', re.IGNORECASE )

    def analyze( self, event, sensor, *args ):
        filePath = _x_( event.data, '?/base.FILE_PATH' )
        cmdLine = _x_( event.data, '?/base.COMMAND_LINE' )
        if filePath is not None and cmdLine is not None:
            if self.vssadmin.match( filePath ) and self.vssadminCommands.match( cmdLine ):
                return True
            elif self.wmic.match( filePath ) and self.wmicCommands.match( cmdLine ):
                return True
        return False
