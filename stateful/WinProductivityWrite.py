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
ProcessDescendant = Actor.importLib( 'analytics/StateAnalysis/descriptors', 'ProcessDescendant' )

class WinProductivityWrite ( object ):
    def __init__( self, fromActor ):
        pass

    def getDescriptor( self ):
        localDocApps = re.compile( r'.*(/|\\)((winword)|(excel)|(powerpnt)|(acrord32))\.exe', re.IGNORECASE )
        suspiciousDocs = re.compile( r'.*\.(exe|bat|vbs|js)', re.IGNORECASE )

        localDocExploit = ProcessDescendant( parentRegExp = localDocApps,
                                             isDirectOnly = False,
                                             documentRegExp = suspiciousDocs,
                                             isForWindows = True,
                                             isForMac = False,
                                             isForLinux = False )
        return localDocExploit