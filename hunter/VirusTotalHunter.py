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
    "type" : "hunter",
    "description" : "Hunter that investigates VT hits.",
    "requirements" : "",
    "feeds" : [],
    "platform" : "all",
    "author" : "maximelb@google.com",
    "version" : "1.0",
    "scaling_factor" : 10000,
    "n_concurrent" : 5,
    "usage" : {}
}
LC_DETECTION_MTD_END
'''
###############################################################################

from beach.actor import Actor
Hunter = Actor.importLib( 'Hunters', 'Hunter' )
_xm_ = Actor.importLib( 'utils/hcp_helpers', '_xm_' )
_x_ = Actor.importLib( 'utils/hcp_helpers', '_x_' )
InvestigationNature = Actor.importLib( 'utils/hcp_helpers', 'InvestigationNature' )
InvestigationConclusion = Actor.importLib( 'utils/hcp_helpers', 'InvestigationConclusion' )
MemoryAccess = Actor.importLib( 'utils/hcp_helpers', 'MemoryAccess' )
MemoryType = Actor.importLib( 'utils/hcp_helpers', 'MemoryType' )
normalAtom = Actor.importLib( 'utils/hcp_helpers', 'normalAtom' )
AgentId = Actor.importLib( 'utils/hcp_helpers', 'AgentId' )

class VirusTotalHunter ( Hunter ):
    detects = ( 'VirusTotalKnownBad', )

    def init( self, parameters, resources ):
        super( VirusTotalHunter, self ).init( parameters )
        self.isMitigate = parameters.get( 'is_mitigate', False )

    def investigate( self, investigation, detect ):
        source = detect[ 'source' ].split( ' / ' )[ 0 ]
        inv_id = detect[ 'detect_id' ]
        data = detect[ 'detect' ]
        thisAtom = _x_( data, 'event/?/hbs.THIS_ATOM' )
        parentAtom = _x_( data, 'event/?/hbs.PARENT_ATOM' )
        originAtom = normalAtom( parentAtom ) if parentAtom is not None else None
        vtReports = data[ 'report' ]
        vtHash = data[ 'hash' ]

        investigation.reportData( 'investigating file hash %s\n event is [here](/explore?atid=%s)\n VT link is [here](https://www.virustotal.com/en/file/%s/analysis/)' % ( vtHash, normalAtom( thisAtom ), vtHash ) )

        # If this is a duplicate investigation abort.
        if investigation.dupeCheck_preInv( vtHash, ttl = 60 * 60 * 24, isPerSensor = False ): return

        # If there is only 1 hit we do additional validation to make sure it's not a false positive.
        if 1 == len( vtReports ):
            locs = self.Models.request( 'get_obj_loc', { 'objects' : [ ( vtHash, 'FILE_HASH' ) ] } )
            if locs.isSuccess:
                if 10 <= len( locs.data ):
                    if investigation.dupeCheck_postInv( vtHash, isPerSensor = False ): return

                    investigation.conclude( "Hash is also found on %s other machines, looks like a false positive" % ( len( vtReports ), ),
                                            InvestigationNature.FALSE_POSITIVE,
                                            InvestigationConclusion.NO_ACTION_TAKEN )
                    return
                else:
                    investigation.reportData( "Hash is only at %s locations" % ( len( vtReports ), ) )
            else:
                investigation.reportData( "Couldn't get hash locations, assuming it's rare: %s" % ( str( locs ), ) )

        # First let's dump the history from the sensor since we rely on a lot.
        histResp = investigation.task( 'fetching history', 
                                       source, 
                                       ( 'history_dump', ) )

        # Wait for the history to get dumped
        if histResp:
            if not histResp.wait( 30 ):
                if histResp.wasReceived:
                    investigation.reportData( 'history dump was received by sensor but did not complete' )
                else:
                    investigation.reportData( 'history dump was not received by sensor, sensor offline?' )
            self.sleep( 5 )

        fileCreates = self.getLastNSecondsOfEventsFrom( 300, source, 'notification.FILE_CREATE' )

        if 1 == len( vtReports ):
            # Check for new executables only on Windows since we can use the file extension to see if it's exec
            if AgentId( source ).isWindows():
                isNewExec = False
                # See if we had any new executables written in the last 5 minutes, if not then it looks like an FP
                for fileCreate in fileCreates:
                    path = _x_( fileCreate, '?/base.FILE_PATH' )
                    if path:
                        path = path.lower()
                        if '.exe' in path or '.dll' in path or '.sys' in path:
                            isNewExec = True
                            break

                if not isNewExec:
                    if investigation.dupeCheck_postInv( vtHash, isPerSensor = False ): return
                    investigation.conclude( "No new executable modules were written in the last 5 minutes, likely an FP",
                                            InvestigationNature.FALSE_POSITIVE,
                                            InvestigationConclusion.NO_ACTION_TAKEN )
                    return

        investigation.reportData( 'Files created in the past 5 minutes\n\n' +
                self.listToMdTable( [ 'File Path' ], 
                                    [ ( _x_( x, '?/base.FILE_PATH' ), ) for x in fileCreates ] ) )

        if investigation.dupeCheck_postInv( vtHash, isPerSensor = False ): return

        investigation.conclude( "Finished investigating",
                                InvestigationNature.OPEN,
                                InvestigationConclusion.REQUIRES_HUMAN )
