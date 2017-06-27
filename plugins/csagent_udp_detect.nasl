#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(26913);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2011/05/24 20:37:07 $");

  script_name(english:"CA BrightStor HSM Engine Detection (UDP)");
  script_summary(english:"Scans for HSM Engine via UDP");

 script_set_attribute(attribute:"synopsis", value:
"A data migration service is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote service is a BrightStor HSM Engine, the engine component of
BrightStor Hierarchical Storage Manager, which is used to manage files
on the remote host as part of an enterprise-grade tiered storage
solution." );
 script_set_attribute(attribute:"see_also", value:"http://www.ca.com/us/products/product.aspx?id=1541" );
 script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/10/04");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");
  script_copyright(english:"This script is Copyright (C) 2007-2011 Tenable Network Security, Inc.");
  script_exclude_keys("Known/udp/2000");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


port = 2000;
if (known_service(port:port, ipproto:"udp")) exit(0);
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

soc = open_sock_udp(port);
if (!soc) exit(0);


req = "RTDM_WHO_ARE_YOU";
send(socket:soc, data:req);
res = recv(socket:soc, length:256);


# If...
if (
  # the response is long-enough and...
  strlen(res) >= 4 &&
  # the software is running
  ":Running:" >< res
)
{
  # Parse the response.
  f = split(res, sep:":", keep:FALSE);

  # If...
  if (
    # the initial field is the packet length and...
    strlen(res) == int(f[0]) &&
    # there's a server name and...
    strlen(f[1]) > 0 &&
    # the engine build looks right and...
    f[4] =~ "^[0-9]+ " &&
    # there's an uptime value
    f[5] =~ "^[0-9]+$"
  )
  {
    # Extract some info for the report.
    info = "";
    # - server name.
    info += "  Server name  : " + f[1] + '\n';
    # - platform.
    info += "  Platform     : " + f[2] + '\n';
    # - engine build.
    info += "  Engine build : " + f[4] + '\n';
    # - uptime.
    info += "  Uptime       : " + f[5] + ' seconds\n';
    # - status.
    info += "  Status       : " + f[3] + '\n';

    # Save some info in the KB.
    set_kb_item(name:"Services/hsm_csagent/" + port + "/platform", value:f[2]);
    set_kb_item(name:"Services/hsm_csagent/" + port + "/build", value:f[4]);

    # Register and report the service.
    register_service(port:port, ipproto:"udp", proto:"hsm_csagent");

    report = string(
      "\n",
      "Nessus was able to gather the following information from the remote\n",
      "HSM Engine :\n",
      "\n",
      info
    );
    security_note(port:port, proto:"udp", extra:report);
  }
}
