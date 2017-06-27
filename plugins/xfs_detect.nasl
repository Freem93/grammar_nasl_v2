#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(26971);
  script_version("$Revision: 1.13 $");

  script_name(english:"X Font Service Detection");
  script_summary(english:"Sends an initial connection request");

 script_set_attribute(attribute:"synopsis", value:
"An X font service is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote service is an X Window Font Service (xfs) daemon, which
serves font files to clients." );
 script_set_attribute(attribute:"see_also", value:"http://www.x.org/docs/FSProtocol/fsproto.pdf" );
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/X_Font_Server" );
 script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired or disable the service
as the use of server-supplied fonts is currently deprecated." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/10/12");
 script_cvs_date("$Date: 2011/03/11 21:18:10 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2007-2011 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 7100);

  exit(0);
}

include("global_settings.inc");
include("byte_func.inc");
include("misc_func.inc");


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery") )
{
  port = get_unknown_svc(7100);
  if (!port) exit(0, "No unknown service.");
  if (silent_service(port) ) exit(0, "Service on port "+port+" is silent.");
}
else port = 7100;

if (known_service(port:port)) exit(0, "Service on port "+port+" has already been identified.");
if (!get_tcp_port_state(port)) exit(0, "Port "+port+" is closed.");


soc = open_sock_tcp(port);
if (!soc) exit(1, "Connection refused on port "+port+".");


# Try to open a connection.
set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

req = 'l' +                            # we're using little-endian byte order
  mkbyte(0) +                          # number of auth
  mkword(0x02) + mkword(0x00) +        # client protocol version (major/minor)
  mkword(0x00);                        # authorization protocols (empty)
send(socket:soc, data:req);


# Read the reply.
res = recv(socket:soc, length:512, min:12);
if (strlen(res) < 12)  exit(1, "Short answer from port "+port+".");

# Parse response elements that appear regardless of the status.
#
# - status
status = getword(blob:res, pos:0);
# - protocol
proto_maj = getword(blob:res, pos:2);
# Make sure this is a real protocol
if ( proto_maj > 4)
 exit(1, "Invalid protocol major ("+proto_maj+") on port "+port+".");

proto_min = getword(blob:res, pos:4);
# - alternate servers
n_alt = getbyte(blob:res, pos:6);
len_alt = getword(blob:res, pos:8) * 4;
if (n_alt && len_alt) list_alt = substr(res, 12, 12+len_alt-1);
else list_alt = "";
# - authorization protocols
auth_index = getbyte(blob:res, pos:7);
len_auth = getword(blob:res, pos:10) * 4;
if (auth_index && len_auth) list_auth = substr(res, 12+len_alt, 12+len_alt+len_auth-1);
else list_auth = "";


# If...
if (
  # Status is Success and auth_index is 0 or...
  (status == 0 && auth_index == 0) ||
  # Status is Continue and auth_index indexes into the authorization protocols or...
  (status == 1 && auth_index >= 1 && auth_index <= len_auth/4) ||
  # Status is Busy and auth_index is 0 or...
  (status == 2 && auth_index == 0) ||
  # Status is Denied and auth_index is 0
  (status == 3 && auth_index == 0)
)
{
  # Extract some info for the report.
  info = "";
  # - protocol version.
  info += "  - Protocol                   : " + proto_maj + '.' + proto_min + '\n';
  # - alternate servers.
  info += "  - Alternate servers          : ";
  if (n_alt)
  {
    info += '\n';
    j = 12+1;
    for (i=0; i<n_alt && j < strlen(res); i++)
    {
      l = getbyte(blob:res, pos:j);
      alt = substr(res, j+1, j+l);
      if ("Invalid packet" >!< alt)
        info += "    - " + alt + '\n';
      j+= l+2;
    }
  }
  else info += 'none\n';
  # - other items if status indicates success.
  if (0 == status)
  {
    i = 12+len_alt+len_auth;
    len_rest = getdword(blob:res, pos:i);
    # - max request size.
    max_req = getword(blob:res, pos:i+4);
    #if (max_req == 0) exit(1, "Null max request size on port "+port+".");
    info += "  - Max request size           : " + 4*max_req + ' bytes\n';
    # - release.
    release = getdword(blob:res, pos:i+8);
    info += "  - Vendor release             : " + release + '\n';
    # - vendor.
    len_vendor = getword(blob:res, pos:i+6);
    if (len_vendor)
    {
      vendor = substr(res, i+12, i+12+len_vendor-1);
      info += "  - Vendor string              : " + vendor + '\n';
    }
    # - list of available fonts.
    #   nb: this won't work properly if max_fonts is so high that the response 
    #       gets split into multiple response packets. 
    max_fonts = 15;
    req2 = mkbyte(0x0d) +              # ListFonts
      mkbyte(0) +                      # unused
      mkword(0x04) +                   # 3+(n+p)/4
      mkdword(max_fonts) +             # max names
      mkword(0x01) +                   # length of pattern (n)
      mkword(0x00) +                   # unused
      "*" +                            # pattern
      crap(data:mkbyte(0x00), length:3); # pad (p)
    send(socket:soc, data:req2);
    res2 = recv(socket:soc, length:6000, min:6);
    if (
      strlen(res2) >= 16 &&
      0 == getbyte(blob:res2, pos:0) &&
      1 == getword(blob:res2, pos:2) &&
      max_fonts >= getdword(blob:res2, pos:12)
    )
    {
      info += "  - Available fonts (up to " + max_fonts + ") : " + '\n';
      nfonts = getdword(blob:res2, pos:12);
      j = 0x10;
      for (i=0; i<nfonts && j < strlen(res2); i++)
      {
        l = getbyte(blob:res2, pos:j);
        font = substr(res2, j+1, j+l);
        info += "    " + font + '\n';
        j+= l+1;
      }
    }
  }

  # Register and report the service.
  register_service(port:port, proto:"xfs");

  if (report_verbosity)
  {
    report = string(
      "\n",
      "Nessus was able to gather the following information from the remote\n",
      "X Font Server :\n",
      "\n",
      info
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
