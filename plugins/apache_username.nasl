#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10766);
 script_version("$Revision: 1.38 $");
 script_cvs_date("$Date: 2015/01/14 15:38:17 $");

 script_cve_id("CVE-2001-1013");
 script_bugtraq_id(3335);
 script_osvdb_id(637);

 script_name(english:"Apache UserDir Directive Username Enumeration");
 script_summary(english:"Checks for the error codes returned by Apache when requesting a nonexistent user name");

 script_set_attribute(attribute:"synopsis", value:
"The remote Apache server can be used to guess the presence of a given
user name on the remote host.");
 script_set_attribute(attribute:"description", value:
"When configured with the 'UserDir' option, requests to URLs containing
a tilde followed by a username will redirect the user to a given
subdirectory in the user home.

For instance, by default, requesting /~root/ displays the HTML
contents from /root/public_html/.

If the username requested does not exist, then Apache will reply with
a different error code. Therefore, an attacker may exploit this
vulnerability to guess the presence of a given user name on the remote
host.");
 script_set_attribute(attribute:"solution", value:"In httpd.conf, set the 'UserDir' to 'disabled'.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2000/07/07");
 script_set_attribute(attribute:"plugin_publication_date", value:"2001/09/18");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2001-2015 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

 script_dependencie("http_version.nasl");
 script_require_keys("www/apache", "Settings/ParanoidReport");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, embedded: 0);

banner = get_http_banner(port:port);
if ( ! banner ) exit(0);
if ( ! egrep(pattern:"Server: .*Apache", string:banner) ) exit(0);

r = http_send_recv3(method:"GET",item:"/~root", port:port);
if (isnull(r)) exit(0);
code = ereg_replace(pattern:"^HTTP/[0-9.]+ ([0-9]+) .*", string: r[0], replace:"\1");
if ( ! code ) exit(0);

r = http_send_recv3(method:"GET", item:"/~admin", port:port);
if (isnull(r)) exit(0);
code2 = ereg_replace(pattern:"^HTTP/[0-9.]+ ([0-9]+) .*", string: r[0], replace:"\1");
if ( ! code2 ) exit(0);


r = http_send_recv3(method:"GET", item:"/~" + rand_str(length:8), port:port);
if (isnull(r)) exit(0);
code3 = ereg_replace(pattern:"^HTTP/[0-9.]+ ([0-9]+) .*", string: r[0], replace:"\1");
if ( ! code3 ) exit(0);


if ( code != code3 || code2 != code3 ) security_warning(port);
