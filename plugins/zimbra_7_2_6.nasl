#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72774);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/04 18:02:24 $");

  script_cve_id("CVE-2013-7217");
  script_bugtraq_id(64415);
  script_osvdb_id(101147);

  script_name(english:"Zimbra Collaboration Server < 7.2.6 / 8.0.6 Unspecified Vulnerability");
  script_summary(english:"Checks version of Zimbra Collaboration Server");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a web application that is affected by an
unspecified vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Zimbra Collaboration Server installed on the remote host is
affected by an unspecified vulnerability.

Note that the vendor has supplied patches for release versions 7.2.2,
7.2.3, 7.2.4, 7.2.5, 8.0.3, 8.0.4, and 8.05.

Also note that Nessus does not identify patch levels for the above
versions.  You will want to verify if the patch has been applied by
executing the command 'zmcontrol -v' from the command line as the
'zimbra' user."
  );
  # http://www.zimbra.com/forums/announcements/67336-critical-security-vulnerability-addressed-7-2-6-8-0-6-maintenance-releases.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?febb129c");
  # http://files.zimbra.com/website/docs/7.2/Zimbra_OS_Release_Notes_7.2.6.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e4581c2");
  # http://files.zimbra.com/website/docs/8.0/Zimbra_OS_Release_Notes_8.0.6.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?19073cb8");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 7.2.6 / 8.0.6 or later or apply the vendor-
supplied patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zimbra:collaboration_suite");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("zimbra_web_detect.nbin");
  script_require_keys("www/zimbra_zcs", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443, 7071);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:443);

install = get_install_from_kb(
  appname      : "zimbra_zcs",
  port         : port,
  exit_on_fail : TRUE
);

app = "Zimbra Collaboration Server";
dir = install["dir"];
version = install["ver"];
install_url = build_url(port:port, qs:dir);

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, app, install_url);
if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  v[i] = int(ver[i]);

# Versions 7.x less than 7.2.6 and 8.x less than 8.0.6 are affected
if (
  (v[0] < 7) ||
  (v[0] == 7 && v[1] < 2) ||
  (v[0] == 7 && v[1] == 2 && v[2] < 6) ||
  (v[0] == 8 && v[1] == 0 && v[2] < 6)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 7.2.6 / 8.0.6\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
