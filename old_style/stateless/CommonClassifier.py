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
    "description" : "Tags sensors with various common useful tags based on execution.",
    "requirements" : "",
    "feeds" : [ "notification.NEW_PROCESS" ],
    "platform" : "common",
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
ObjectTypes = Actor.importLib( 'utils/ObjectsDb', 'ObjectTypes' )
StatelessActor = Actor.importLib( 'Detects', 'StatelessActor' )
_xm_ = Actor.importLib( 'utils/hcp_helpers', '_xm_' )

class CommonClassifier ( StatelessActor ):
    def init( self, parameters, resources ):
        super( CommonClassifier, self ).init( parameters, resources )
        self.classifiers = {
          'webserver' : re.compile( r'.*(?:\\|/)(?:w3wp\.exe|httpd\.exe|httpd|apache2|nginx|uwsgi|lighttpd.exe|lighttpd|php-cgi.exe|node.exe|node)$', re.IGNORECASE ),
          'developer' : re.compile( r'.*(?:\\|/)(?:devenv\.exe|msbuild\.exe|go|javac|javac\.exe|gcc|clang)$', re.IGNORECASE ),
          'database' : re.compile( r'.*(?:\\|/)(?:mysqld\.exe|mysqld|cassandra|oracle\.exe|mongos\.exe|mongos|postgres\.exe|postgres)$', re.IGNORECASE ),
        }

    def process( self, detects, msg ):
        routing, event, mtd = msg.data

        filePath = event.values()[ 0 ].get( 'base.FILE_PATH', None )
        if filePath is not None:
            for tag, r in self.classifiers.iteritems():
                if tag not in routing[ 'tags' ] and r.match( filePath ):
                    self.tag( routing[ 'aid' ], tag, ttl = ( 60 * 60 * 24 * 7 ) )
