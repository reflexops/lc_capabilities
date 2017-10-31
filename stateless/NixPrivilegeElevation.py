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

class NixPrivilegeElevation ( object ):
    def __init__( self ):
        pass

    def analyze( self, event, sensor, *args ):
        procUid = _x_( event.data, '?/base.USER_ID' )
        procPath = _x_( event.data, '?/base.FILE_PATH' )
        if procUid is not None and 0 == procUid and procPath is not None and not procPath.lower().endswith( 'sudo' ):
            parentUid = _x_( event.data, '?/base.PARENT/base.USER_ID' )
            if parentUid is not None and 0 != parentUid:
                return True
        return False
