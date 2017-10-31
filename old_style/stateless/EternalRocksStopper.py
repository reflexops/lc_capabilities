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
    "description" : "Detects very specifically EternalRocks instances and stops them, from analysis at https://github.com/stamparm/EternalRocks/blob/master/README.md",
    "requirements" : "",
    "feeds" : [ "notification.NEW_PROCESS", "notification.CODE_IDENTITY", "notification.EXISTING_PROCESS" ],
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
from sets import Set
ObjectTypes = Actor.importLib( 'utils/ObjectsDb', 'ObjectTypes' )
StatelessActor = Actor.importLib( 'Detects', 'StatelessActor' )
_x_ = Actor.importLib( 'utils/hcp_helpers', '_x_' )
normalAtom = Actor.importLib( 'utils/hcp_helpers', 'normalAtom' )

class EternalRocksStopper ( StatelessActor ):
    def init( self, parameters, resources ):
        super( EternalRocksStopper, self ).init( parameters, resources )
        self.payloadDir = re.compile( '.*\\Program Files\\Microsoft Updates\\.*', re.IGNORECASE )
        self.hashes = Set( [ '1ee894c0b91f3b2f836288c22ebeab44798f222f17c255f557af2260b8c6a32d',
                             '20240431d6eb6816453651b58b37f53950fcc3f0929813806525c5fd97cdc0e1',
                             '2094d105ec70aa98866a83b38a22614cff906b2cf0a08970ed59887383ee7b70',
                             '23eeb35780faf868a7b17b8e8da364d71bae0e46c1ababddddddecbdbd2c2c64',
                             '44472436a5b46d19cb34fa0e74924e4efc80dfa2ed491773a2852b03853221a2',
                             '589af04a85dc66ec6b94123142a17cf194decd61f5d79e76183db026010e0d31',
                             '64442cceb7d618e70c62d461cfaafdb8e653b8d98ac4765a6b3d8fd1ea3bce15',
                             '6bc73659a9f251eef5c4e4e4aa7c05ff95b3df58cde829686ceee8bd845f3442',
                             '70ec0e2b6f9ff88b54618a5f7fbd55b383cf62f8e7c3795c25e2f613bfddf45d',
                             '7b8674c8f0f7c0963f2c04c35ae880e87d4c8ed836fc651e8c976197468bd98a',
                             '94189147ba9749fd0f184fe94b345b7385348361480360a59f12adf477f61c97',
                             '9bd32162e0a50f8661fd19e3b26ff65868ab5ea636916bd54c244b0148bd9c1b',
                             'a77c61e86bc69fdc909560bb7a0fa1dd61ee6c86afceb9ea17462a97e7114ab0',
                             'a7c387b4929f51e38706d8b0f8641e032253b07bc2869a450dfa3df5663d7392',
                             'ad8965e531424cb34120bf0c1b4b98d4ab769bed534d9a36583364e9572332fa',
                             'aedd0c47daa35f291e670e3feadaed11d9b8fe12c05982f16c909a57bf39ca35',
                             'b2ca4093b2e0271cb7a3230118843fccc094e0160a0968994ed9f10c8702d867',
                             'c4762489488f797b4b33382c8b1b71c94a42c846f1f28e0e118c83fe032848f0',
                             'c999bf5da5ea3960408d3cba154f965d3436b497ac9d4959b412bfcd956c8491',
                             'cf8533849ee5e82023ad7adbdbd6543cb6db596c53048b1a0c00b3643a72db30',
                             'd43c10a2c983049d4a32487ab1e8fe7727646052228554e0112f6651f4833d2c',
                             'd86af736644e20e62807f03c49f4d0ad7de9cbd0723049f34ec79f8c7308fdd5',
                             'e049d8f69ddee0c2d360c27b98fa9e61b7202bb0d3884dd3ca63f8aa288422dc',
                             'e77306d2e3d656fa04856f658885803243aef204760889ca2c09fbe9ba36581d',
                             'f152ed03e4383592ce7dd548c34f73da53fc457ce8f26d165155a331cde643a9',
                             'fc75410aa8f76154f5ae8fe035b9a13c76f6e132077346101a0d673ed9f3a0dd' ] )

    def process( self, detects, msg ):
        routing, event, mtd = msg.data
        
        doDeny = False
        filePath = _x_( event, '?/base.FILE_PATH' )
        if filePath is not None:
            if self.payloadDir.match( filePath ):
                doDeny = True
        if not doDeny:
            fileHash = _x_( event, '?/base.HASH' )
            if fileHash is not None:
                if fileHash.encode( 'hex' ) in self.hashes:
                    doDeny = True

        if doDeny:
            relevantAtom = None
            if 'notification.CODE_IDENTITY' == routing[ 'event_type' ]:
                # The parent may be a MODULE_LOAD in which case this won't do much but still good.
                relevantAtom = _x_( event, '?/hbs.PARENT_ATOM' )
            else:
                relevantAtom = _x_( event, '?/hbs.THIS_ATOM' )
            if relevantAtom is not None:
                detects.add( 100,
                             'eternalrocks instance detected, denying it',
                             event,
                             ( ( 'deny_tree', normalAtom( relevantAtom ) ),
                               ( 'history_dump', ) ) )
            else:
                detects.add( 100,
                             'eternalrocks instance detected, could not find parent to deny',
                             event,
                             ( ( 'history_dump', ), ) )
