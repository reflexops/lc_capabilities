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
    "type" : "stateful",
    "description" : "Detects a suspicious payload executed from within a scripting engine.",
    "requirements" : "",
    "feeds" : [],
    "platform" : "windows",
    "author" : "maximelb@google.com",
    "version" : "1.0",
    "scaling_factor" : 500,
    "n_concurrent" : 5,
    "usage" : {}
}
LC_DETECTION_MTD_END
'''
###############################################################################

from beach.actor import Actor
import re
ProcessDescendant = Actor.importLib( 'analytics/StateAnalysis/descriptors', 'ProcessDescendant' )
StatefulActor = Actor.importLib( 'Detects', 'StatefulActor' )

class WinScriptedPayload ( StatefulActor ):
    def initMachines( self, parameters ):
        self.shardingKey = 'agentid'

        scriptEngines = re.compile( r'.*(/|\\)(((w|c)script))\.exe', re.IGNORECASE )
        sensitiveApps = re.compile( r'.*(/|\\)((((rundll32)|(explorer)|(iexplore)|(svchost)|(icacls)|(bcdedit)|(wbadmin)|(attrib)|(calc)|(notepad))\.exe)|((?<!\.exe)$))', re.IGNORECASE )
        suspiciousDocs = re.compile( r'.*\.(exe|bat|vbs|js|hta|scr)', re.IGNORECASE )
        
        scriptedPayload = ProcessDescendant( name = 'windows_scripted_payload',
                                             priority = 90,
                                             summary = 'A script engine has executed what looks like a suspicious payload',
                                             parentRegExp = scriptEngines,
                                             isDirectOnly = False,
                                             childRegExp = sensitiveApps )

        self.addStateMachineDescriptor( scriptedPayload )

        scriptedPayloadDrop = ProcessDescendant( name = 'windows_scripted_payload_drop',
                                                 priority = 70,
                                                 summary = 'A script engine has dropped a suspicious file',
                                                 parentRegExp = scriptEngines,
                                                 isDirectOnly = False,
                                                 documentRegExp = suspiciousDocs )

        self.addStateMachineDescriptor( scriptedPayloadDrop )