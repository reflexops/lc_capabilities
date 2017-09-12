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

###############################################################################
# Metadata
'''
LC_DETECTION_MTD_START
{
    "type" : "stateless",
    "description" : "Detects processes that should be unprivileged but are not.",
    "requirements" : "",
    "feeds" : [ "notification.NEW_PROCESS" ],
    "platform" : "windows",
    "author" : "maximelb@google.com",
    "version" : "1.0",
    "scaling_factor" : 1000,
    "n_concurrent" : 5,
    "usage" : {}
}
LC_DETECTION_MTD_END
'''
###############################################################################

from beach.actor import Actor
import re
StatelessActor = Actor.importLib( 'Detects', 'StatelessActor' )
_x_ = Actor.importLib( 'utils/hcp_helpers', '_x_' )

class UnprivilegedProcesses ( StatelessActor ):
    def init( self, parameters, resources ):
        super( UnprivilegedProcesses, self ).init( parameters, resources )
        self.processes = re.compile( r'.*(/|\\)((chrome)|(firefox)|(iexplore)|(winword)|(excel)|(powerpnt)|(outlook)|(acrord32))\.exe', re.IGNORECASE )
        self.blackListAccounts = re.compile( r'^nt authority.*', re.IGNORECASE )

    def process( self, detects, msg ):
        routing, event, mtd = msg.data
        
        filePath = _x_( event, '?/base.FILE_PATH' )
        userName = _x_( event, '?/base.USER_NAME' )
        if filePath is not None and userName is not None:
            if self.processes.match( filePath ) and self.blackListAccounts.match( userName ):
                    detects.add( 90,
                                 'process created from privileged account',
                                 event )
