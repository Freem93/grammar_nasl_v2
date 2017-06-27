#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70764);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/26 16:22:51 $");

  script_name(english:"vBulletin upgrade.php Accessible");
  script_summary(english:"Tries to get access the upgrade.php script");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A bulletin board system hosted on the remote web server has a security
weakness."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The vBulletin install hosted on the remote host allows access to the
upgrade.php script.  The vendor recommends that access to this be
disabled as a precaution. 

Note that the version may be affected by a security bypass vulnerability
due to an error in the configuration mechanism.  This could allow a
remote, unauthenticated attacker to create a new user account with
administrator privileges by sending a specially crafted request to the
'install/upgrade.php' or 'core/install/upgrade.php' script. This could
then allow the attacker to gain administrative access to the vBulletin
install. 

Note that Nessus has not tested for the vulnerability itself, but
instead checked only to see if upgrade.php is accessible without
credentials."
  );
  # http://www.vbulletin.com/forum/forum/vbulletin-announcements/vbulletin-announcements_aa/3991423-vbulletin-install-system-exploit-vbulletin-4-1-vbulletin-5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?997509a7");
  script_set_attribute(attribute:"solution", value:
"Remove the 'install/upgrade.php' or 'core/install/upgrade.php' script
as well as refer to the supplied URL for additional steps from the
vendor.  Additionally, conduct a full security review of the host, as it
may have been compromised."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vbulletin:vbulletin");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("vbulletin_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/vBulletin");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(
  appname      : "vBulletin",
  port         : port,
  exit_on_fail : TRUE
);

dir = install["dir"];
install_url = build_url(qs:dir, port:port);

vuln = FALSE;
foreach path (make_list("/install/", "/core/install/"))
{
  url = path + "upgrade.php";

  res = http_send_recv3(
    method : "GET",
    item   : dir + url,
    port   : port,
    fetch404     : TRUE,
    exit_on_fail : TRUE
  );

  if (
    "404 Not Found" >!< res[1] &&
    res[2] =~ "\<title\>vBulletin (.*) Upgrade System" &&
    'src="vbulletin-upgrade.js"' >< res[2] &&
    'name="customerid" id="customerid"' >< res[2]
  )
  {
    vuln = TRUE;
    break;
  }
}

if (!vuln) audit(AUDIT_WEB_APP_NOT_AFFECTED, "vBulletin", install_url);

if (report_verbosity > 0)
{
  header = 'Nessus was able to verify this issue with the following URL';
  report = get_vuln_report(
    items  : dir + url,
    port   : port,
    header : header
  );
  security_hole(port:port, extra:report);
}
else security_hole(port);
