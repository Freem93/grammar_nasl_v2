#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90246);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/31 17:32:20 $");

  script_cve_id("CVE-2016-3657");
  script_osvdb_id(135052);

  script_name(english:"Palo Alto Networks PAN-OS GlobalProtect Web Portal RCE (PAN-SA-2016-0005)");
  script_summary(english:"Checks response from GlobalProtect web portal.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Palo Alto Networks PAN-OS running on the remote host is affected
by a remote code execution vulnerability in the GlobalProtect web
portal due to improper validation of user-supplied input when handling
SSL VPN requests. An unauthenticated, remote attacker can exploit
this, via a crafted request, to cause an overflow condition, resulting
in a denial of service or the execution of arbitrary code.

Note that the remote PAN-OS is reportedly affected by other
vulnerabilities as well; however, Nessus has not tested for these.");
  script_set_attribute(attribute:"see_also", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/38");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Palo Alto Networks PAN-OS version 5.0.18 / 6.0.13 /
6.1.10 / 7.0.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:paloaltonetworks:pan-os");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/panweb");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

get_kb_item_or_exit("www/panweb");

port = get_http_port(default:443, embedded:TRUE);

banner = get_http_banner(port:port);
if(banner && "PanWeb Server" >!< banner)
  audit(AUDIT_WRONG_WEB_SERVER, port, "a Palo Alto GlobalProtect portal");   

url = "/global-protect/login.esp";
user = crap(data:'%C2%A2',length:0x60*3);
postdata =
  'prot=https%3A' +
  '&server=' + get_host_ip() +
  '&inputStr=' +
  '&action=getsoftware' +
  '&user=' + user +
  '&passwd=bar' +
  '&ok=Login';

res = http_send_recv3(
  method:'POST',
  item:url,
  port:port,
  content_type:'application/x-www-form-urlencoded',
  data:postdata,
  follow_redirect:1,
  exit_on_fail:TRUE
);

# GlobalProtect portal login page is disabled or 
# the web server is not a GlobalProtect portal
if(res[0] =~ "^HTTP/[0-9.]+ 404") 
  audit(AUDIT_LISTEN_NOT_VULN, "web server ", port);

if(! res[2])
  audit(AUDIT_RESP_BAD, port, 'a login request: no response body');

req = http_last_sent_request();
app = "Palo Alto GlobalProtect Portal";

# Look for:
#  var respMsg = <msg>; 
match = eregmatch(string: res[2], pattern:"var[ \t]+respMsg[ \t]*=[ \t]*(.*)\;");
if(match)
{
  respMsg = match[1];
  if("Authentication failed: Invalid username or password" >< respMsg)
  {
    security_report_v4(
      port       : port,
      severity   : SECURITY_HOLE,
      request    : make_list(req),
      generic    : TRUE
    );
  }
  else if (
    # seen in 7.0.5
    ("invalid user input" >< respMsg)
    # seen in 7.0.6, 6.1.11
    || (respMsg =~"Authentication failt?ure: Invalid username or password")
    )
    audit(AUDIT_LISTEN_NOT_VULN, app, port);
  else
    audit(AUDIT_RESP_BAD, port, 'a login request: unexpected respMsg: ' + respMsg);
}
else
  audit(AUDIT_RESP_BAD, port, 'a login request: respMsg not found in HTTP response body');
  