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
ProcessBurst = Actor.importLib( 'analytics/StateAnalysis/descriptors', 'ProcessBurst' )

class WinReconTools ( object ):
    def __init__( self, fromActor ):
        pass

    def getDescriptor( self ):
        reconBurst = ProcessBurst( procRegExp = re.compile( r'.*(/|\\)((ipconfig)|(arp)|(route)|(ping)|(vssadmin)|(traceroute)|(nslookup)|(netstat)|(wmic)|(net\d?)|(whoami)|(systeminfo))\.exe', re.IGNORECASE),
                                   nPerBurst = 4,
                                   withinMilliSeconds = 5 * 1000,
                                   isForWindows = True,
                                   isForMac = False,
                                   isForLinux = False )
        return reconBurst