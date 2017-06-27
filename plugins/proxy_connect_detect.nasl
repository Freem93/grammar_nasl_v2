#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34473);
  script_version("$Revision: 1.8 $");

  script_name(english:"HTTP CONNECT Proxy Detection");
  script_summary(english:"Tries to proxy connections to ports on the target itself");

 script_set_attribute(attribute:"synopsis", value:
"A web proxy is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote service supports the HTTP CONNECT method for tunneling
connections through an HTTP connection." );
 script_set_attribute(attribute:"solution", value:
"Make sure use of this service is in agreement with your organization's
security policy." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/10/22");
 script_cvs_date("$Date: 2011/03/14 21:48:11 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2008-2011 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl", "http_version.nasl");
  script_require_ports("Services/unknown", 808, 3128, 8080);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery") ) 
{
  ports = get_kb_list("Services/unknown");
}
else ports = make_list();
ports = add_port_in_list(list:ports, port:808);             # used by CCProxy
ports = add_port_in_list(list:ports, port:3128);
ports = add_port_in_list(list:ports, port:8080);


# Loop through each port.
foreach port (ports)
{
  if (service_is_unknown(port:port) && get_tcp_port_state(port))
  {
    # Try to connect to some ports on the target.
    target_ports = make_list(443, port, 80);
    foreach target_port (target_ports)
    {
      if (!get_tcp_port_state(target_port)) continue;

      req = http_mk_proxy_request(method:"CONNECT", host: get_host_ip(), port: target_port);
      r = http_send_recv_req(port: port, req: req);
      if (isnull(r)) break;

      # If the response looks ok...
      if (r[0] =~ "^HTTP/[0-9.]+ +200 ")
      {
        # Register and report the service.
        register_service(port:port, proto:"http_proxy");
        security_note(port);

        # Set some additional KB items.
        kb_base = "http_proxy/" + port + "/";
	banner = strcat(r[0], r[1]);

        set_kb_item(name:kb_base+"banner", value:banner);
        if ("proxy-agent: ccproxy" >< tolower(banner)) 
          set_kb_item(name:kb_base+"CCProxy", value:TRUE);

        break;
      }
    }
  }
}
