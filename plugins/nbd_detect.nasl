#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20340);
  script_version("$Revision: 1.9 $");

  script_name(english:"Network Block Device Server Detection");
  script_summary(english:"Detects a NBD server");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a remote storage service." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a Network Block Device (NBD) server, which
allows one Linux host to use another as one of its block devices." );
 script_set_attribute(attribute:"see_also", value:"http://nbd.sourceforge.net/" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/12/24");
 script_cvs_date("$Date: 2011/03/11 21:18:09 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 2000);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


# nb: 2000 is used in the examples in the man pages but 
#     there's no default port.
if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery") ) {
  port = get_unknown_svc(2000);
  if ( ! port ) exit(0);
}
else port = 2000;
if (!get_tcp_port_state(port)) exit(0);


# Establish a connection and examine the banner.
soc = open_sock_tcp(port);
if (soc) {
  res = recv(socket:soc, length:256);
  if (res == NULL) exit(0);

  # It's an NBD server if ...
  #
  # nb: clieserv.h from the source describes the initial packets from the server.
  if (
    # it is the right size and...
    strlen(res) == 152 &&
    # it starts with INIT_PASSWD and...
    stridx(res, "NBDMAGIC") == 0 &&
    # it's followed by cliserv_magic
    stridx(res, raw_string(0x00, 0x00, 0x42, 0x02, 0x81, 0x86, 0x12, 0x53)) == 8
  ) {
    # Register and report the service.
    register_service(port:port, ipproto:"tcp", proto:"nbd");

    security_note(port);
  }

  close(soc);
}
