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

from beach.actor import Actor
import re
_x_ = Actor.importLib( 'utils/hcp_helpers', '_x_' )

class UnprivilegedProcesses ( object ):
    def __init__( self, fromActor ):
        self.processes = re.compile( r'.*(/|\\)((chrome)|(firefox)|(iexplore)|(winword)|(excel)|(powerpnt)|(outlook)|(acrord32))\.exe', re.IGNORECASE )
        self.blackListAccounts = re.compile( r'^nt authority.*', re.IGNORECASE )

    def analyze( self, event, sensor, *args ):
        if not sensor.aid.isWindows():
            return False

        if event.dataType not in ( 'notification.NEW_PROCESS', ):
            return False

        filePath = _x_( event.data, '?/base.FILE_PATH' )
        userName = _x_( event.data, '?/base.USER_NAME' )
        parentUserName = _x_( event.data, '?/base.PARENT/base.USER_NAME' )
        if filePath is not None and userName is not None and parentUserName is not None:
            if self.processes.match( filePath ) and ( self.blackListAccounts.match( userName ) or 
                                                      self.blackListAccounts.match( parentUserName ) ):
                return True
        return False