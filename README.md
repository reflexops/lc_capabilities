# LimaCharlie Core Detection Capabilities

These detections and hunters are designed to be used in conjunction with [LimaCharlie](https://github.com/refractionpoint/limacharlie).

## How to Use
To load or unload capabilities, go to the Capabilities menu in the LimaCharlie web ui. Copy the URL of a detection or patrol straight from your 
browser on GitHub and paste it in the form. Give that capability a name in the form and click Add Capability. 
That's it, the latest version gets loaded from the repository directly. You can also copy, tweak and load them locally.

## What to Load

### Core Patrol
Loading the core patrol will bring in all the stateless and stateful detections that should be low risk and false positive.
These detections are passive in that they do not mitigate any of the threats they detect.


### Patrol Active Mitigation
Loading this patrol will bring in active mitigations against some threats. This means it will automatically coordinate with the sensor
to stop actively, usually by killing specific processes a threat it detects. You should understand that this is potentially more risky.
