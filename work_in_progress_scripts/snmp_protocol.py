from pysnmp.hlapi import *

def get_snmp_data(ip_address, oid):
    for (errorIndication,
         errorStatus,
         errorIndex,
         varBinds) in nextCmd(SnmpEngine(),
                              CommunityData('public'),
                              UdpTransportTarget((ip_address, 161)),
                              ContextData(),
                              ObjectType(ObjectIdentity(oid)),
                              lexicographicMode=False):

        if errorIndication:
            print(errorIndication)
            break
        elif errorStatus:
            print(f"{errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex) - 1][0] or '?'}")
            break
        else:
            for varBind in varBinds:
                print(f"{varBind[0].prettyPrint()} = {varBind[1].prettyPrint()}")

# Example: Get system information from an SNMP-enabled device
get_snmp_data('10.80.1.223', '1.3.6.1.2.1.1')
