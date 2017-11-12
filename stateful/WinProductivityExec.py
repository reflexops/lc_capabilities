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

class WinProductivityExec ( object ):
    def __init__( self, fromActor ):
        pass

    def getDescriptor( self ):
        productivityApps = re.compile( r'.*(/|\\)((chrome)|(firefox)|(iexplore)|(winword)|(excel)|(powerpnt)|(outlook)|(acrord32))\.exe', re.IGNORECASE )
        sensitiveApps = re.compile( r'.*(/|\\)((cmd)|(nslookup)|(ipconfig)|(wmic)|(whoami)|(systeminfo)|(powershell))\.exe', re.IGNORECASE )
        
        productivityDocExploit = ProcessDescendant( parentRegExp = productivityApps,
                                                    isDirectOnly = False,
                                                    childRegExp = sensitiveApps )

        return productivityDocExploit