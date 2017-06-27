#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42932);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2011/03/11 21:18:10 $");

  script_name(english:"SqueezeCenter Discovery Service Detection");
  script_summary(english:"Sends a discovery packet");

  script_set_attribute(
    attribute:"synopsis", 
    value:"A streaming audio service is listening on the remote host."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote service implements the UDP discovery protocol used by 
Squeezebox Server (formerly known as SlimServer and SqueezeCenter)
to discover other streaming audio servers in the network."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://wiki.slimdevices.com/index.php/CLI"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Ensure that use of this software agrees with your organization's 
acceptable use and security policies."
  );
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/30");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");
  script_copyright(english:"This script is Copyright (C) 2009-2011 Tenable Network Security, Inc.");

  exit(0);
}


include("global_settings.inc");
include("byte_func.inc");
include("misc_func.inc");


port = 3483;
if (!get_udp_port_state(port)) exit(1, "UDP port "+port+" is not open.");
if (known_service(port:port, ipproto:"udp")) exit(0, "The service listening on UDP port "+port+" is already known.");


soc = open_sock_udp(port);
if (!soc) exit(1, "Can't open socket on UDP port "+port+".");


# Send a discovery packet.
req = 'eIPAD' + mkbyte(0) +
      'NAME' + mkbyte(0) +
      'JSON' + mkbyte(0);
send(socket:soc, data:req);
res = recv(socket:soc, length:512);
close(soc);
if (strlen(res)< 10) exit(0);


# If it looks like a valid reply...
if (
  substr_at_offset(blob:'ENAME', str:res, offset:0) &&
  substr_at_offset(blob:'JSON', str:res, offset:6+getbyte(blob:res, pos:5))
)
{
  # Register and report the service.
  register_service(port:port, ipproto:"udp", proto:"squeeze_discovery");

  info = "";
  if (report_verbosity > 1)
  {
    i = 6;
    l = getbyte(blob:res, pos:i-1);
    datum = substr(res, i, i+l-1);
    info += '  Music library name : ' + datum + '\n';

    i += l + 4 + 1;
    l = getbyte(blob:res, pos:i-1);
    datum = substr(res, i, i+l-1);
    if (ereg(string:datum, pattern:"^[0-9]+$"))
      info += '  JSON port          : ' + datum + '\n';
  }

  if (info)
  {
    report = '\n' +
      'Nessus collected the following information from the remote service :\n' +
      '\n' +
      info;
    security_note(port:port, proto:"udp", extra:report);
  }
  else security_note(port:port, proto:"udp");
}
