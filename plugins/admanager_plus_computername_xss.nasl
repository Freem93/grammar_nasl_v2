#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(46787);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/01/13 06:57:50 $");

  script_cve_id("CVE-2010-5050");
  script_bugtraq_id(40355);
  script_osvdb_id(64857);
  script_xref(name:"Secunia", value:"39901");

  script_name(english:"ManageEngine ADManager Plus 'computerName' Parameter XSS");
  script_summary(english:"Attempts a non-persistent XSS");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application on the remote host has a cross-site scripting
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of ADManager Plus running on the remote web server has a
cross-site scripting vulnerability.  Input to the 'computerName'
parameter of '/jsp/admin/tools/remote_share.jsp' is not properly
sanitized.

A remote attacker could exploit this by tricking a user into
requesting a maliciously crafted URL, resulting in the execution of
arbitrary script code."
  );
  script_set_attribute(attribute:"solution", value:"There is no known solution at this time.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("admanager_plus_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8080);
  script_require_keys("www/admanager_plus");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:8080);
install = get_install_from_kb(appname:'admanager_plus', port:port, exit_on_fail:TRUE);

dir = install['dir']+'/jsp/admin/tools/';
cgi = 'remote_share.jsp';
xss = '</title><script>alert(\''+SCRIPT_NAME+'-'+unixtime()+'\')</script>';
expected_output = xss+'</title>';

exploited = test_cgi_xss(
  port:port,
  dirs:make_list(dir),
  cgi:cgi,
  qs:'computerName='+xss,
  pass_str:expected_output,
  ctrl_re:'<title>Remote Desktop Sharing - '
);

if (!exploited)
  exit(0, build_url(qs:dir+cgi, port:port) + " is not affected.");

