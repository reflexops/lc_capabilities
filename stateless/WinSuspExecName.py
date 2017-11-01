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
_xm_ = Actor.importLib( 'utils/hcp_helpers', '_xm_' )

class WinSuspExecName ( object ):
    def __init__( self, fromActor ):
        self.susp = re.compile( r'.*((\.txt)|(\.doc.?)|(\.ppt.?)|(\.xls.?)|(\.zip)|(\.rar)|(\.rtf)|(\.jpg)|(\.gif)|(\.pdf)|(\.wmi)|(\.avi)|( {5}.*))\.exe', re.IGNORECASE )
        self.rtlo = re.compile( r'.*\xE2\x80\x8F.*' )

    def analyze( self, event, sensor, *args ):
        for filePath in _xm_( event.data, '?/base.FILE_PATH' ):
            if self.susp.match( filePath ) or self.rtlo.match( filePath ):
                return True
        return False
