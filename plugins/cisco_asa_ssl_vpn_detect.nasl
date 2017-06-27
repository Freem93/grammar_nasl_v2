#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(42796);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/03/03 16:02:44 $");

  script_name(english:"CISCO ASA SSL VPN Detection");
  script_summary(english:"Checks for the login screen.");

  script_set_attribute(attribute:'synopsis', value:
"The remote host is an SSL VPN server.");
  script_set_attribute(attribute:'description', value:
"The remote host is a Cisco Adaptive Security Appliance (ASA) running
an SSL VPN server.");
  script_set_attribute(attribute:'solution', value: "n/a");
  script_set_attribute(attribute:'risk_factor', value:'None');
  script_set_attribute(attribute:'plugin_publication_date', value:'2009/11/12');
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
  script_family(english:"Service detection");

  script_dependencies("find_service2.nasl", "http_version.nasl");
  script_require_ports("Services/www", 443);
  exit(0);
}

include("audit.inc");
include('global_settings.inc');
include('misc_func.inc');
include('http.inc');

port = get_http_port(default:443, embedded:TRUE);

init_cookiejar();

res =
  http_send_recv3(method:"GET", port:port, item:"/+CSCOE+/logon.html", exit_on_fail:TRUE);
if (res[0] =~ "^HTTP/[0-9.]+ +200 " &&
    res[2] =~ 'action="/\\+webvpn\\+/index.html' &&
    res[2] =~ 'document\\.cookie="webvpnlogin='
)
{
  register_service(port:port, proto:"cisco-ssl-vpn-svr");

  if (report_verbosity > 0)
  {
    report =
      'The login page for the remote VPN can be accessed using the following URL :' +
      '\n' + 
      '\n  ' + build_url(port:port, qs:"/+CSCOE+/logon.html");
      
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
else
  audit(AUDIT_HOST_NOT, "a Cisco ASA SSL VPN");

