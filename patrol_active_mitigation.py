###############################################################################
# Metadata
'''
LC_PATROL_MTD_START
{
    "description" : "Collection of all core LimaCharlie.io detections.",
    "stateless" : "WanaCryStopper,",
    "stateful" : "",
    "hunter" : "",
    "author" : "maximelb@google.com",
    "version" : "1.0"
}
LC_PATROL_MTD_END
'''
###############################################################################


#######################################
# stateless/WanaCrytopper
# This actor looks for the basic unique
# executable name from WanaCry and 
# immediately issues a kill on the entire
# malicious process tree.
# Parameters:
#######################################
Patrol( 'WanaCryStopper',
        initialInstances = 1,
        maxInstances = None,
        relaunchOnFailure = True,
        onFailureCall = None,
        scalingFactor = 2000,
        actorArgs = ( 'stateless/WanaCryStopper',
                      [ 'analytics/stateless/common/notification.NEW_PROCESS/wanacrystopper1.0' ] ),
        actorKwArgs = {
            'parameters' : {},
            'secretIdent' : 'analysis/01e9a19d-78e1-4c37-9a6e-37cb592e3897',
            'trustedIdents' : [ 'analysis/01e9a19d-78e1-4c37-9a6e-37cb592e3897' ],
            'n_concurrent' : 5,
            'strategy' : 'repulsion' } )
