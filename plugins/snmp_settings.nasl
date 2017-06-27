#
# (C) Tenable Network Security, Inc.
#

# @PREFERENCES@

MAX_ADDITIONAL_SNMP_COMMUNITIES = 3;
MAX_ADDITIONAL_SNMP_PORTS = 3;

include("compat.inc");

if (description)
{
  script_id(19762);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2016/01/05 18:44:51 $");

  script_name(english:"SNMP settings");
  script_summary(english:"Sets SNMP settings.");

  script_set_attribute(attribute:"synopsis", value:"Sets SNMP settings.");
  script_set_attribute(attribute:"description", value:
"This script just sets global variables (SNMP community string and
SNMP port) and does not perform any security checks.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/09/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_category(ACT_GATHER_INFO);
  script_family(english:"Settings");

  script_add_preference(name:"Community name :", type:"entry", value:"public");
  for ( i = 1 ; i <= MAX_ADDITIONAL_SNMP_COMMUNITIES ; i ++ )
    script_add_preference(name:"Community name (" + i + ") :", type:"entry", value:"");

  script_add_preference(name:"UDP port :", type:"entry", value:"161");
  for ( i = 1 ; i <= MAX_ADDITIONAL_SNMP_PORTS ; i ++ )
    script_add_preference(name:"Additional UDP port (" + i + ") :", type:"entry", value:"");

  script_add_preference(name:"SNMPv3 user name :", type:"entry", value:"");
  script_add_preference(name:"SNMPv3 authentication password :", type:"password", value:"");
  script_add_preference(name:"SNMPv3 authentication algorithm :", type:"radio", value:"MD5;SHA1");
  script_add_preference(name:"SNMPv3 privacy password :", type:"password", value:"");
  script_add_preference(name:"SNMPv3 privacy algorithm :", type:"radio", value:"AES;DES");

  exit(0);
}

include ("global_settings.inc");
include ("snmp_func.inc");
include ("misc_func.inc");

snmp_port = 0;

function do_initial_snmp_get( community, ports )
{
  local_var port, soc, index;

  if (isnull(community) || strlen(community) == 0) return NULL;

  foreach port (ports)
  {
    soc = open_sock_udp(port);
    if (soc)
    {
      index = snmp_request_next(socket:soc, community:community, oid:"1.3.6.1.2.1.1.1.0", timeout:2);
      close(soc);

      if (
        !isnull(index) &&
        # Sun ...
        index[1] != "/var/snmp/snmpdx.st" &&
        index[1] != "/etc/snmp/conf" &&
        # HP MSL 8048
        index[0] != "1.3.6.1.2.1.11.6.0"
      )
      {
        snmp_port = port;
        return index;
      }
    }
  }
  return NULL;
}

index = community = NULL;

p = script_get_preference("UDP port :");
if (!p) p = 161;
ports = make_list(p);

for (i=1; i<=MAX_ADDITIONAL_SNMP_PORTS; i++)
{
  p = script_get_preference("Additional UDP port (" + i + ") :");
  if (!isnull(p))
  {
    p = int(p);
    if (p >= 1 && p <= 65535) ports = make_list(ports, p);
  }
}
ports = list_uniq(ports);


# SNMPv3
snmpv3_user = script_get_preference("SNMPv3 user name :");
snmpv3_auth = script_get_preference("SNMPv3 authentication password :");
snmpv3_aalg = script_get_preference("SNMPv3 authentication algorithm :");
snmpv3_priv = script_get_preference("SNMPv3 privacy password :");
snmpv3_palg = script_get_preference("SNMPv3 privacy algorithm :");
snmpv3_port = script_get_preference("SNMPv3 port :");

if ( snmpv3_user )
  set_kb_item( name:"SNMP/v3/username", value:snmpv3_user );

# set defaults for Nessus < 6.x and SC < 5.x
# Nessus will send the default value as the entire list (e.g. "MD5;SHA1")
# SC will send the default as the empty string
if ('MD5' >< snmpv3_aalg || snmpv3_aalg == '')
  snmpv3_aalg = 'MD5';
if ('AES' >< snmpv3_palg || snmpv3_palg == '')
  snmpv3_palg = 'AES';

# Determine what level of SNMPv3 authentication has been requested.
if  ( snmpv3_user && snmpv3_auth && snmpv3_aalg && snmpv3_priv && snmpv3_palg )
  snmpv3_security_level = USM_LEVEL_AUTH_PRIV;   # authPriv
else if  ( snmpv3_user && snmpv3_auth && snmpv3_aalg )
  snmpv3_security_level = USM_LEVEL_AUTH_NO_PRIV;   # authNoPriv
else
  snmpv3_security_level = USM_LEVEL_NO_AUTH_NO_PRIV;   # noAuthNoPriv

if ( snmpv3_user )
{
  auth_blob = base64( str:string( snmpv3_user, ';',
                                  snmpv3_auth, ';',
                                  snmpv3_aalg, ';',
                                  snmpv3_priv, ';',
                                  snmpv3_palg, ';',
                                  snmpv3_security_level ) );
  community = ';' + auth_blob;
  SNMP_VERSION = 3; # SNMPv3

  snmpv3_ports = ports;
  if (snmpv3_port)
    snmpv3_ports = make_list(snmpv3_port);
  index = do_initial_snmp_get(community:community, ports:snmpv3_ports);
}

community_v1_v2c = script_get_preference( 'Community name :' );
if ( isnull( community_v1_v2c ) )
  community_v1_v2c = "public";

if (isnull(index))
{
  SNMP_VERSION = 1; # SNMPv2c
  index = do_initial_snmp_get(community:community_v1_v2c, ports:ports);
  if  ( index )
    community = community_v1_v2c;
}

if (isnull(index))
{
  SNMP_VERSION = 0; # SNMPv1
  index = do_initial_snmp_get(community:community_v1_v2c, ports:ports);
  if  ( index )
    community = community_v1_v2c;
}

if ( isnull(index) )
{
 for ( i = 1 ; i <= MAX_ADDITIONAL_SNMP_COMMUNITIES || strlen(community_v1_v2c) > 0 ; i ++ )
 {
  community_v1_v2c = script_get_preference( 'Community name (' + i + ') :' );
  if ( strlen(community_v1_v2c) == 0 ) continue;
  SNMP_VERSION = 1; # SNMPv2c
  index = do_initial_snmp_get(community:community_v1_v2c, ports:ports);
  if ( index ) { community = community_v1_v2c ; break ; }
  SNMP_VERSION = 0; # SNMPv1
  index = do_initial_snmp_get(community:community_v1_v2c, ports:ports);
  if ( index ) { community = community_v1_v2c ; break ; }
 }
}

if (isnull(index)) exit(0, "Not able to authenticate via SNMP.");

if (!snmp_port) exit (1, "Failed to identify the SNMP port.");

set_kb_item( name:"SNMP/community", value:community );
set_kb_item( name:"SNMP/community_v1_v2c", value:community_v1_v2c );
set_kb_item( name:"SNMP/port", value:snmp_port );
set_kb_item( name:"SNMP/version", value:SNMP_VERSION );

if(SNMP_VERSION < 3)
{
  report = 'The remote SNMP server accepts cleartext community strings.';
  set_kb_item(name:"PCI/ClearTextCreds/" + snmp_port, value:report);
}

if ( SNMP_VERSION == 0 ) set_kb_item( name:"SNMP/version_v1", value:TRUE);
register_service(port:snmp_port, proto:"snmp", ipproto:"udp");
