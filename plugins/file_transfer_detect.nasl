#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(31660);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2011/03/11 21:18:08 $");

  script_name(english:"File Transfer (P2P) Detection");
  script_summary(english:"Tries to transfer a nonexistent file");

 script_set_attribute(attribute:"synopsis", value:
"A file transfer service is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote service is File Transfer, a peer-to-peer file transfer
tool. 

Note that, as of version 1.2f at least, the application has no support
for authenticating access so anyone who can access the port can
potentially retrieve or upload files." );
 script_set_attribute(attribute:"see_also", value:"http://file-transfer.sourceforge.net/" );
 script_set_attribute(attribute:"solution", value:
"Make sure use of this program fits with your corporate security
policy." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/03/26");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");
  script_copyright(english:"This script is Copyright (C) 2008-2011 Tenable Network Security, Inc.");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 14567);
  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


if (
  thorough_tests &&
  !get_kb_item("global_settings/disable_service_discovery")
)
{
  port = get_unknown_svc(14567);
  if (!port) exit(0);
  if (silent_service(port)) exit(0); 
}
else port = 14567;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Read the version string.
ver = recv(socket:soc, length:32, min:4);
if (strlen(ver) == 0 || ver !~ "^[0-9][0-9.]+[a-z]$") exit(0);


# Send it back.
send(socket:soc, data:ver);


# Request a nonexistent file.
file = string(SCRIPT_NAME, "-", unixtime());
req = "#FILERQST " + file + " 0 1" + mkbyte(0);
req = mkbyte(4) + mkbyte(strlen(req)) + req;
send(socket:soc, data:req);
res = recv(socket:soc, length:2);
if (
  strlen(res) == 2 &&
  getbyte(blob:res, pos:0) == 4 &&
  getbyte(blob:res, pos:1) != 0
)
{
  len = getbyte(blob:res, pos:1);
  res = recv(socket:soc, length:len);
  if (
    strlen(res) == len &&
    res =~ '^#FILE(RECV|RRFD)'
  )
  {
    # Register / report the service.
    register_service(port:port, proto:"file_transfer");
    security_note(port);
  }
}
