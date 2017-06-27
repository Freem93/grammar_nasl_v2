#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(31645);
  script_version("$Revision: 1.8 $");

  script_name(english:"Acronis Agent Detection (UDP)");
  script_summary(english:"Sends a broadcast packet");

 script_set_attribute(attribute:"synopsis", value:
"A backup service is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote service is an Acronis Agent, a component of Acronis
TrueImage that allows for managing backup and restore operations on
the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://www.acronis.com/enterprise/products/ATIES/windows-agent.html" );
 script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/03/25");
 script_cvs_date("$Date: 2011/05/24 20:37:07 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2008-2011 Tenable Network Security, Inc.");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");


port = 9876;
if (known_service(port:port, ipproto:"udp"))
 exit(0, "The service on UDP port "+port+" is already known.");
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

soc = open_sock_udp(port);
if ( ! soc ) exit(1, "UDP connection failed to port "+port+".");


# Simulate a Management Console broadcast in search of agents.
set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

req = raw_string(0x37, 0xe5, 0x02, 0x00, 0x00, 0x00);
send(socket:soc, data:req);

res = recv(socket:soc, length:64);
if (strlen(res) == 0) exit(0, "No answer from UDP port "+port+".");


# If...
if (
  # the packet length looks right and...
  strlen(res) > 18 &&
  # the packet starts with the expected sequence and...
  stridx(res, raw_string(0xb6, 0xa1, 0x01, 0x00)) == 0 &&
  # the word starting at offset 0x10 points after the computer name
  getword(blob:res, pos:0x10) == (getword(blob:res, pos:0x0c) + 2*getword(blob:res, pos:0x0e))
)
{
  # Extract the computer name for the report.
  ofs = getword(blob:res, pos:0x0c);
  l = getword(blob:res, pos:0x0e);
  name = "";
  if (i+l+l < strlen(res))
  {
    for (i=0; i<l+l; i+=2)
    {
      if (getbyte(blob:res, pos:ofs+i+1) == 0) name += res[ofs+i];
      else
      {
        name = "";
        break;
      }
    }
  }

  # Register and report the service.
  register_service(port:port, ipproto:"udp", proto:"acronis_agent");

  if (name && report_verbosity)
  {
    report = string(
      "\n",
      "Here is some information about the remote Acronis Agent that Nessus\n",
      "was able to collect :\n",
      "\n",
      "  Computer name : ", name, "\n"
    );
    security_note(port:port, proto:"udp", extra:report);
  }
  else security_note(port:port, proto:"udp");
}
