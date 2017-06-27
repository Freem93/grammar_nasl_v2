#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(20092);
  script_version("$Revision: 1.8 $");

  script_name(english:"YIFF Sound Server Detection");
  script_summary(english:"Detects a YIFF sound server");

  script_set_attribute(
    attribute:"synopsis",
    value:"A network sound server is listening on the remote port."
  );
  script_set_attribute(  attribute:"description",   value:
"The remote host is running a YIFF sound server, an open source
network sound server."  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://freshmeat.net/projects/yiff/"
  );
  script_set_attribute(  attribute:"solution",   value:
"Ensure that use of this software is in agreement with your
organization's acceptable use and security policies."  );
  script_set_attribute(
    attribute:"risk_factor", 
    value:"None"
  );
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/10/27");
 script_cvs_date("$Date: 2011/03/11 21:18:10 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");

  script_require_ports("Services/unknown", 9433);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery") ) {
  port = get_unknown_svc(9433);
  if (!port)exit(0);
}
else port = 9433;
if (!get_tcp_port_state(port)) exit(0);


# Send a request for sound attributes, which is the first packet yplay sends.
soc = open_sock_tcp(port);
if (!soc) exit(0);

# nb: the actual name is irrelevant.
file = string("/usr/share/sounds/", SCRIPT_NAME, ".wav");
req = raw_string(
                                        # packet size, to be added later
  0x00, 0x0a,                           # constant (YSoundObjectAttributes from include/Y2/Y.h)
  0x00, 0x00,                           # constant (YSoundObjectAttributesGet from include/Y2/Y.h)
  file
);
req = raw_string(
  0x00, 0x00, 0x00, (strlen(req)+4),    # packet size, as promised
  req
);

send(socket:soc, data:req);


# Read the response.
res = recv(socket:soc, length:64);
if (isnull(res)) exit(0);


# It's a YIFF sound server if...
if (
  # it looks like a sound attributes response and...
  strlen(res) >= 22 && 
  substr(res, 4, 7) == raw_string(0x00, 0x0a, 0x00, 0x01) && 
  (
    # either the packet has our filename or...
    substr(res, 22) == file ||
    # it doesn't have a filename at all (ie, filename not found).
    strlen(res) == 22
  )
)
{
  # Register and report the service.
  register_service(port:port, ipproto:"tcp", proto:"yiff");

  security_note(port);
}
