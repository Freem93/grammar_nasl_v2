#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if (description)
{
  script_id(40448);
  script_version( '$Revision: 1.7 $' );
  script_cvs_date("$Date: 2013/01/19 01:10:18 $");

  script_name(english:"SNMP Supported Protocols Detection");
  script_summary(english:"Reports all supported SNMP versions.");

  script_set_attribute( attribute:'synopsis', value:
"This plugin reports all the protocol versions successfully negotiated
with the remote SNMP agent."  );
  script_set_attribute( attribute:'description', value:
"Extend the SNMP settings data already gathered by testing for\
SNMP versions other than the highest negotiated."  );
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute( attribute:'plugin_publication_date', value:'2009/07/31' );
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category( ACT_GATHER_INFO );
  script_family( english:'SNMP' );

  script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");

  script_require_keys( 'SNMP/community', 'SNMP/community_v1_v2c', 'SNMP/version' );
  exit(0);
}

include ('snmp_func.inc');
include ('misc_func.inc');

function do_initial_snmp_get( community, port )
{
  local_var soc, result;
  soc = open_sock_udp( port );
  if ( ! soc )
    exit( 1, 'Unable to open socket' );
  result = snmp_request( socket:soc, community:community, oid:"1.3.6.1.2.1.1.1.0", timeout:2 );
  close(soc);
  return result;
}

supported = make_list ( 0, 0, 0, 0 );

v3_supported = get_kb_item( 'SNMP/v3/Supported' );
community_v1_v2c = get_kb_item( 'SNMP/community_v1_v2c' );
version = get_kb_item( 'SNMP/version' );
port = get_kb_item( 'SNMP/port' );
if ( !port )
   port = 161;

# We already know that this version works.
if  ( !isnull( version ) && version <= 3 )
  supported[ version ] = 1;

if  ( version != 3 && !isnull( v3_supported ) )
  supported[ 3 ] = 1;

# We have working SNMPv3 creds, let's try for SNMPv1/2c
if ( v3_supported )
{
  set_snmp_version( version:1 ); # SNMPv2c
  res = do_initial_snmp_get( community:community_v1_v2c, port:port );
  if  ( !isnull( res ) )
    supported[ SNMP_VERSION ] = 1;
  reset_snmp_version();

  set_snmp_version( version:0 ); # SNMPv1
  res = do_initial_snmp_get( community:community_v1_v2c, port:port );
  if  ( !isnull( res ) )
    supported[ SNMP_VERSION ] = 1;
  reset_snmp_version();
}

# Otherwise, we've found a community string that works
# We already know if v3 works from v3_supported,
# But, there may be a lower supported version
# If version is 1, try version 0.  If version is 0, we have already tried 1 and it failed.
else if ( version == 1 )
{
  set_snmp_version( version:0 ); # SNMPv1
  res = do_initial_snmp_get( community:community_v1_v2c, port:port );
  if  ( !isnull( res ) )
    supported[ SNMP_VERSION ] = 1;
  reset_snmp_version();
}

version_result = NULL;
report = '';
for ( i=0; i<max_index( supported ); i++ )
{
  if  ( supported[ i ] )
  {
    version_result = version_result | supported[ i ];
    version = 'SNMPv';
    if ( i == 0 )
      version += '1';
    else if( i == 1 )
      version += '2c';
    else if( i == 3 )
      version += '3';
    report += string( 'This host supports SNMP version ', version, '.\n' );
  }
}

if ( ! version_result )
  exit ( 0, 'No SNMP support found.' );

security_note( port:port, proto:'udp', extra:report );
