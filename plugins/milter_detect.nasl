#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(30058);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/10/13 15:19:33 $");

  script_name(english:"Milter Detection");
  script_summary(english:"Searches for an agent via TCP");

  script_set_attribute(attribute:"synopsis", value:
"A mail filtering service is listening on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote service is a milter, which provides an interface between a
mail transfer agent (MTA) such as sendmail and an application such as
SpamAssassin or ClamAV for filtering messages.");
  script_set_attribute(attribute:"see_also", value:"https://www.milter.org/");
  script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired.");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/26");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown");
  script_require_keys("Settings/ThoroughTests");
  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


if (!thorough_tests) exit(0, "The 'Perform thorough tests' setting is not set.");
if (get_kb_item("global_settings/disable_service_discovery"))
 exit(0, "Service discovery is disabled");

port = get_unknown_svc(0);             # nb: no default
if (!port) exit(0, "No unknown port");
if (!get_tcp_port_state(port)) exit(0, "Port "+port+" is closed");


soc = open_sock_tcp(port);
if (!soc) exit(1, "Connection refused on port "+port+".");


# Initiate a connection.
set_byte_order(BYTE_ORDER_BIG_ENDIAN);

# - negotiate options.
req1 = 
  'O' +                                 # SMFIC_OPTNEG
  mkdword(2) +                          # SMFI_VERSION (2)
  mkdword(0x7f) +                       # options
  mkdword(0);                           # possible protocol content
req1 = mkdword(strlen(req1)) + req1;
send(socket:soc, data:req1);
res1_1 = recv(socket:soc, length:4);
if (strlen(res1_1) != 4) exit(0, "Data does match expected value on port "+port+".");
len = getdword(blob:res1_1, pos:0);
if (len == 0) exit(0, "Length is null on port "+port+".");
if (len > 1024*1024) exit(0, "Length is too big on port "+port+".");
res1_2 = recv(socket:soc, length:len);
if (strlen(res1_2) != len) exit(0, "Short read on port "+port+".");
res1 = res1_1 + res1_2;


# If ...
if (
  # it's the right size and...
  strlen(res1) == 17 && 
  # an SMFIC_OPTNEG response
  getbyte(blob:res1, pos:4) == ord('O')
)
{
  # Send connection information.
  hostname = "localhost";

  req2 = 
    'C' +                                 # SMFIC_CONNECT
    hostname + mkbyte(0) +                # host name
    'U';                                  # protocol family (U => unknown)
  req2 = mkdword(strlen(req2)) + req2;
  send(socket:soc, data:req2);
  res2_1 = recv(socket:soc, length:4);
  if (strlen(res2_1) != 4) exit(0, "Short read on port "+port+".");
  len = getdword(blob:res2_1, pos:0);
  if (len == 0) exit(0, "Length is null on port "+port+".");
  if (len > 1024*1024) exit(0, "Length is too big on port "+port+".");
  res2_2 = recv(socket:soc, length:len);
  if (strlen(res2_2) != len) exit(0, "Short read on port "+port+".");
  res2 = res2_1 + res2_2;

  # If ...
  if (
    # it's the right size and...
    strlen(res2) == 5 && 
    # a valid response code.
    res2_2 =~ '^[acprt]$'
  )
  {
    # Extract some info.
    info = '  Milter Protocol Version : 2\n\n';

    bitmask = getdword(blob:res1, pos:9);
    if (bitmask)
    {
      info += '  Possible Actions :\n';
      if (bitmask & 0x01) info += '     Add headers (SMFIR_ADDHEADER)\n';
      if (bitmask & 0x02) info += '     Change body chunks (SMFIR_REPLBODY)\n';
      if (bitmask & 0x04) info += '     Add recipients (SMFIR_ADDRCPT)\n';
      if (bitmask & 0x08) info += '     Remove recipients (SMFIR_DELRCPT)\n';
      if (bitmask & 0x10) info += '     Change or delete headers (SMFIR_CHGHEADER)\n';
      if (bitmask & 0x20) info += '     Quarantine message (SMFIR_QUARANTINE)\n';
      info += '\n';
    }

    bitmask = getdword(blob:res1, pos:14);
    if (bitmask)
    {
      info += '  Undesired Protocol Content :\n';
      if (bitmask & 0x01) info += '    Skip SMFIC_CONNECT\n';
      if (bitmask & 0x02) info += '    Skip SMFIC_HELO\n';
      if (bitmask & 0x04) info += '    Skip SMFIC_MAIL\n';
      if (bitmask & 0x08) info += '    Skip SMFIC_RCPT\n';
      if (bitmask & 0x10) info += '    Skip SMFIC_BODY\n';
      if (bitmask & 0x20) info += '    Skip SMFIC_HEADER\n';
      if (bitmask & 0x40) info += '    Skip SMFIC_EOH\n';
      info += '\n';
    }

    # Register and report the service.
    register_service(port:port, ipproto:"tcp", proto:"milter");

    if (report_verbosity)
    {
      report = string(
        "\n",
        "Here is some information about the remote milter :\n",
        "\n",
        info
      );
      security_note(port:port, extra:report);
    }
    else security_note(port);
  }
}
