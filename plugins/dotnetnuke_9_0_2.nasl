#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99762);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/05/02 13:34:08 $");

  script_osvdb_id(152363);

  script_name(english:"DNN (DotNetNuke) 6.2.x < 9.0.2 User Profile Information Disclosure");
  script_summary(english:"Checks the version of DNN.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP.NET application that is affected
by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of DNN Platform (formerly DotNetNuke) running on the
remote host is 6.2 or later but prior to 9.0.2. It is, therefore,
affected by an unspecified flaw that allows an unauthenticated, remote
attacker to disclose sensitive user profile property information.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # http://www.dnnsoftware.com/community-blog/cid/155416/902-release-and-security-patch
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?49eaf34f");
  script_set_attribute(attribute:"see_also", value:"http://www.dnnsoftware.com/platform/manage/security-center");
  script_set_attribute(attribute:"solution", value:
"Upgrade to DNN Platform version 9.0.2 or later, or apply the
DNNSecurityFix1 security patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dotnetnuke:dotnetnuke");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("dotnetnuke_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/DNN");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "DNN";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, asp:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
version = install['version'];

install_url = build_url(qs:dir, port:port);

fix = '9.0.2';

# Versions 6.2 - 9.0.1 are affected only if SecurityFix1 not present
hotfix1 = get_kb_item("DNN/SecurityFix1");

if ((isnull(hotfix1) || hotfix1 != 1) &&
  version =~ "^6.2(\.|$)|^7\.|^8\.|^9\." &&
  (ver_compare(ver:version, fix:fix, strict:FALSE) == -1))
{

  report =
    '\n  URL               : ' + install_url +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix + ' or apply DNNSecurityFix1' +
    '\n';

  security_report_v4(extra:report, port:port, severity:SECURITY_WARNING);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
