#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32399);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2011/05/24 20:37:08 $");

  script_name(english:"MDAP Service Detection");
  script_summary(english:"Sends an MDAP ANT-SEARCH request");

 script_set_attribute(attribute:"synopsis", value:
"A network service is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote service supports the Multi Directory Access Protocol
(MDAP), which is used to multicast commands to certain types of
network devices, such as Thompson ADSL modems." );
 script_set_attribute(attribute:"see_also", value:"http://use.perl.org/~dpavlin/journal/34918" );
 script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/05/22");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2008-2011 Tenable Network Security, Inc.");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


port = 3235;
if (known_service(port:port, ipproto:"udp")) exit(0);

soc = open_sock_udp(port);
if (!soc) exit(0);
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

# Send a search request.
req = string(
  "ANT-SEARCH MDAP/1.1\r\n",
  "46"
);
send(socket:soc, data:req);
res = recv(socket:soc, length:1024);
close(soc);


# If it looks like a reply...
if (
  strlen(res) > 0 &&
  stridx(res, "REPLY-ANT-SEARCH MDAP/") == 0 &&
  "ANT-ID" >< res
)
{
  # Register and report the service.
  register_service(port:port, ipproto:"udp", proto:"mdap");

  if (report_verbosity)
  {
    report = string(
      "\n",
      "The remote server sent the following in response to an 'ANT-SEARCH'\n",
      "request :\n",
      "\n",
      res
    );
    security_note(port:port, proto:"udp", extra:report);
  }
  else security_note(port:port, proto:"udp");
}
