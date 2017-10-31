# Copyright 2017 Google, inc
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

class AppLockerBypasses ( object ):
    def __init__( self, fromActor ):
        self.patterns = [ ( re.compile( r'.*rundll32\.exe$', re.IGNORECASE ), re.compile( r'.*(mshtml,RunHTMLApplication)|(shell32.dll,Control_RunDLL).*', re.IGNORECASE ) ),
                          ( re.compile( r'.*regsvr32\.exe$', re.IGNORECASE ), re.compile( r'.*/\.sct.*', re.IGNORECASE ) ),
                          ( re.compile( r'.*regsvcs\.exe$', re.IGNORECASE ), re.compile( r'.*/U.+regsvcs\.dll.*', re.IGNORECASE ) ),
                          ( re.compile( r'.*regasm\.exe$', re.IGNORECASE ), re.compile( r'.*/U.+regsvcs\.dll.*', re.IGNORECASE ) ),
                          ( re.compile( r'.*bginfo\.exe$', re.IGNORECASE ), re.compile( r'.*\.bgi.*', re.IGNORECASE ) ) ]

    def analyze( self, event, sensor, *args ):
        filePath = _x_( event.data, '?/base.FILE_PATH' )
        cmdLine = _x_( event.data, '?base.COMMAND_LINE' )
        if filePath is not None and cmdLine is not None:
            for pattern in self.patterns:
                if pattern[ 0 ].match( filePath ) and pattern[ 1 ].match( cmdLine ):
                    return True
        return False
