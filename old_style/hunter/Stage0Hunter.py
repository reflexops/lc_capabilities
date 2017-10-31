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
    "description" : "Generic investigation of what looks like a stage 0.",
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

class Stage0Hunter ( Hunter ):
    detects = ( 'WinSuspExecLoc', 
                'WinSuspExecName', 
                'MacSuspExecLoc',
                'windows_scripted_payload', 'windows_scripted_payload_drop',
                'windows_productivity_doc_exploit', 'windows_local_doc_exploit', )

    def init( self, parameters, resources ):
        super( Stage0Hunter, self ).init( parameters )

    def investigate( self, investigation, detect ):
        source = detect[ 'source' ].split( ' / ' )[ 0 ]
        inv_id = detect[ 'detect_id' ]
        data = detect[ 'detect' ]
        pid = _x_( data, '?/base.PROCESS_ID' )
        originTs = _x_( data, '?/base.TIMESTAMP' )
        stage0Path = _x_( data, '?/base.FILE_PATH' )
        thisAtom = _x_( data, '?/hbs.THIS_ATOM' )
        parentAtom = _x_( data, '?/hbs.PARENT_ATOM' )
        originAtom = parentAtom
        originEvent = data

        investigation.reportData( 'investigating file %s' % ( stage0Path, ), data = { "explore" : self.exploreLink( thisAtom ) } )
    

        if stage0Path is not None:
            if investigation.dupeCheck_preInv( stage0Path, ttl = 60 * 60 * 24 * 7, isPerSensor = True ): return

        # Before we investigate we'll try to get some cached information
        investigation.task( 'get the file creations for the next minute', 
                            source, 
                            ( 'exfil_add', 
                              'notification.FILE_CREATE', 
                              '--expire', 
                              60 ),
                            isNeedResp = False )
        investigation.task( 'get udp network connections for the next minute', 
                            source, 
                            ( 'exfil_add', 
                              'notification.NEW_UDP4_CONNECTION', 
                              '--expire', 
                              60 ),
                            isNeedResp = False )
        investigation.task( 'get tcp network connections for the next minute', 
                            source, 
                            ( 'exfil_add', 
                              'notification.NEW_TCP4_CONNECTION', 
                              '--expire', 
                              60 ),
                            isNeedResp = False )
        histResp = investigation.task( 'fetching history', 
                                       source, 
                                       ( 'history_dump', ) )
        getFileResp = investigation.task( 'getting the stage0 file',
                                          source,
                                          ( 'file_get', stage0Path ) )

        # Wait for the history to be flushed
        histResp.wait( 10 )

        # First, let's crawl up the parent events to see if we know
        # what each one is, we're looking for the root event that
        # is well known.
        investigation.reportData( 'looking at the parents of the process until we find a well known process.' )
        for parentEvent in self.crawlUpParentTree( None, rootAtom = parentAtom ):
            originAtom = _x_( parentEvent, '?/hbs.THIS_ATOM' )
            originEvent = parentEvent
            parentEventType = parentEvent.keys()[ 0 ]

            # This is likely going to be a process, but we're going to try to be even
            # more generic and just look at the path to see if we know it.
            parentPath = _x_( parentEvent, '?/base.FILE_PATH' )
            if parentPath is None:
                investigation.reportData( 'parent has no path, unsure on how to process it' )
                break

            # Let's see on how many boxes we've seen this path before.
            parentObjInfo = self.getObjectInfo( parentPath, 'FILE_PATH' )
            if parentObjInfo is None or 0 == len( parentObjInfo ):
                investigation.reportData( 'could not find information on path %s' % parentPath )
                nLocs = 0
            else:
                nLocs = parentObjInfo[ 'locs' ][ parentObjInfo[ 'id' ] ]
            if nLocs > 5:
                break
        
        investigation.reportData( 'origin (%s) of bad behavior as far as we can tell: %s' % ( self.exploreLink( originAtom ), parentPath ) )

        originPid = _x_( originEvent, '?/base.PROCESS_ID' )

        memMapResp = investigation.task( 'looking for possible malicious code in the origin process', 
                                         source, 
                                         ( 'mem_map', '--pid', originPid ) )

        # Let's analyze the memory map to see if we can find suspicious memory regions that we could fetch.
        if memMapResp.wait( 120 ):
            memMap = memMapResp.responses.pop()
            suspiciousRegions = []
            memMap = _xm_( memMap, '?/base.MEMORY_MAP' )
            if memMap is not None:
                for region in memMap:
                    if 'base.FILE_PATH' in region or 'base.MODULE_NAME' in region: continue

                    if region[ 'base.MEMORY_ACCESS' ] in ( MemoryAccess.EXECUTE,
                                                           MemoryAccess.EXECUTE_READ,
                                                           MemoryAccess.EXECUTE_WRITE,
                                                           MemoryAccess.EXECUTE_WRITE_COPY,
                                                           MemoryAccess.EXECUTE_WRITE ):
                        suspiciousRegions.append( region )
            if 0 < len( suspiciousRegions ):
                suspiciousRegions = [ { "base" : hex( _x_( r, 'base.BASE_ADDRESS' ) ),
                                        "size" : hex( _x_( r, 'base.MEMORY_SIZE' ) ),
                                        "type" : MemoryType.lookup[ _x_( r, 'base.MEMORY_TYPE' ) ],
                                        "access" : MemoryAccess.lookup[ _x_( r, 'base.MEMORY_ACCESS' ) ] } for r in suspiciousRegions ]
                investigation.reportData( 'suspicious memory regions:', data = suspiciousRegions )
            else:
                investigation.reportData( 'no suspicious memory region found (%s total regions)' % len( memMap ) )
        elif memMapResp.wasReceived:
            investigation.reportData( 'mem map command received by sensor but no response' )
        else:
            investigation.reportData( 'never received confirmation of mem map from sensor' )

        # Let's see if we managed to get the file from the sensor.
        if getFileResp.wait( 120 ):
            getFile = getFileResp.responses.pop()
            thisAtom = _x_( getFile, '?/hbs.THIS_ATOM' )
            investigation.reportData( 'retrieved file %s' % ( stage0Path, ), data = { "explore" : self.exploreLink( thisAtom ) } )
        elif getFileResp.wasReceived:
            investigation.reportData( "get file couldn't reach sensor" )
        else:
            investigation.reportData( 'never received the file' )

        # Let's get the list of documents of interest (also cached) created in the last minute.
        lastDocs = self.getEventsNSecondsAround( 60, originTs / 1000, source, 'notification.NEW_DOCUMENT' )
        lastDocs = [ { "file" : _x_( doc, '?/base.FILE_PATH' ),
                       "hash" : _x_( doc, '?/base.HASH' ) } for doc in lastDocs ]
        investigation.reportData( 'found %s documents created in the last minute' % ( len( lastDocs ), ), data = lastDocs )

        # Let's see if any of the documents are known bad.
        isBadDocFound = False
        for docPath, docHash in lastDocs:
            vtReport, mdVtReport = self.getVTReport( docHash )
            if vtReport is not None and 0 < len( vtReport ):
                isBadDocFound = True
                investigation.reportData( 'the document with hash *%s* has the following virus total hits:', data = vtReport )

        if not isBadDocFound:
            investigation.reportData( 'no recent file had hits on virus total' )


        # Check for new code loading
        lastCode = self.getEventsNSecondsAround( 60, originTs / 1000, source, 'notification.CODE_IDENTITY' )
        lastCode = [ { "file" : _x_( code, '?/base.FILE_PATH' ),
                       "hash" : _x_( code, '?/base.HASH' ) } for code in lastCode ]
        investigation.reportData( 'found %s new pieces of code in the last minute' % ( len( lastCode ), ), data = lastCode )

        isBadCodeFound = False
        for codePath, codeHash in lastCode:
            vtReport, mdVtReport = self.getVTReport( codeHash )
            if vtReport is not None and 0 < len( vtReport ):
                isBadCodeFound = True
                investigation.reportData( 'the code with hash *%s* has the following virus total hits:', data = vtReport )

        if not isBadCodeFound:
            investigation.reportData( 'no recent code had hits on virus total' )


        # Check for rare domains being queried
        lastDns = self.getEventsNSecondsAround( 60, originTs / 1000, source, 'notification.DNS_REQUEST' )
        lastDns = [ _x_( dns, '?/base.DOMAIN_NAME' ) for dns in lastDns ]
        totalDns = len( lastDns )
        lastDns = [ x for x in lastDns if not self.isAlexaDomain( x ) ]
        investigation.reportData( 'found %s DNS queries (%s queries, minus Alexa top million) in the last minute' % ( len( lastDns ), totalDns ), data = lastDns )


        # Check the network activity
        lastConn = self.getEventsNSecondsAround( 60, originTs / 1000, source, 'notification.NEW_TCP4_CONNECTION' )
        lastConn = [ { "pid" : _x_( conn, '?/base.PROCESS_ID' ),
                       "source" : '%s:%s' % ( _x_( conn, '?/base.SOURCE/base.IP_ADDRESS' ), _x_( conn, '?/base.SOURCE/base.PORT' ) ),
                       "dest" : '%s:%s' % ( _x_( conn, '?/base.DESTINATION/base.IP_ADDRESS' ), _x_( conn, '?/base.DESTINATION/base.PORT' ) ) } for conn in lastConn ]
        investigation.reportData( 'found %s TCP connections in the last minute' % ( len( lastConn ), ), data = lastConn )

        childrenEvents = self.getChildrenAtoms( originAtom )
        childrenFileCreate = []
        if childrenEvents is not None:
            for event in childrenEvents:
                if event.keys()[ 0 ] in ( 'notification.FILE_CREATE', ):
                    childrenFileCreate.append( event )
            if 0 != len( childrenFileCreate ):
                investigation.reportData( 'events of interest from the original process', data = { "events" : childrenFileCreate } )

        if stage0Path is not None:
            if investigation.dupeCheck_postInv( stage0Path, isPerSensor = True ): return

        # Concluding the investigation
        investigation.conclude( 'unsure on the nature of this event but lots of context was gathered',
                                InvestigationNature.OPEN,
                                InvestigationConclusion.REQUIRES_HUMAN )
