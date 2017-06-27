#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50545);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2012/10/18 21:50:26 $");

  script_name(english:"NetSupport Manager Gateway Detection");
  script_summary(english:"Detects NetSupport Manager Gateway");

  script_set_attribute(attribute:"synopsis",value:
"The remote host has an application that is configured to act as a
gateway.");
  script_set_attribute(attribute:"description",value:
"NetSupport Manager Gateway, a secure method to establish connections
between NetSupport control and client PCs, is installed on the remote
system.");
  script_set_attribute(attribute:"see_also",value:"http://www.netsupportsoftware.com/whitepapers/Gateway.pdf");
  script_set_attribute(attribute:"solution",value:"n/a");
  script_set_attribute(attribute:"risk_factor",value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/10");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:netsupportsoftware:netsupport_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2012 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 443);
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

http_set_read_timeout(2 * get_read_timeout());

# get_http_port(), doesn't find this, so connect to each
# port individually.
ports = add_port_in_list(list:get_kb_list("Services/www"), port:443);
ports = add_port_in_list(list:ports, port:3085); # default port in v9.x

# nb: 
#   Webserver response is erratic
# - Won't respond to GET requests
# - Won't respond if User-Agent is not recognized
# - Only responds to /fakeurl.htm in a POST request.
# - Can take some time to respond.

foreach port (ports)
{
  if (get_port_state(port))
  {
    banner = get_http_banner(port:port);
    if (banner && "NetSupport Gateway" >!< banner) continue;
 
    # *required otherwise http API breaks against this webserver.
    http_disable_keep_alive();

    cmd = 'CMD=POLL\r\nINFO=1\r\nACK=1\r\n';
    res = http_send_recv3(
        method:"POST", 
        item:"/fakeurl.htm", 
        version:11,
        port: port,
        add_headers: make_array('User-Agent', 'NetSupport Manager/1.0'),
        data: cmd);

    if (
      "Server: NetSupport Gateway/" >< res[1] && 
      (
        ("CMD=ENCD" >< res[2] && "DATA=" >< res[2]) || # v11.0
        "CMD=ACK" >< res[2]  # v10.0
      )
    )
    {
      set_kb_item(name:"Services/www/"+port+"/embedded", value:TRUE);

      if ("CMD=ENCD" >< res[2] && "DATA=" >< res[2]) 
        set_kb_item(name:"netsupport-gateway/" + port + "/encrypted_communication", value:TRUE);

      register_service(port:port, ipproto:"tcp", proto:"netsupport-gateway");
      security_note(port);
      exit(0);
    }
  }
}
