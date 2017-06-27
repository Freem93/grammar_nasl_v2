#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82079);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/16 14:02:53 $");

  script_cve_id("CVE-2014-5005","CVE-2014-5006","CVE-2014-5007");
  script_bugtraq_id(69491,69493,69494);
  script_osvdb_id(100008,110643,110644);
  script_xref(name:"EDB-ID", value:"34594");

  script_name(english:"ManageEngine Desktop Central Arbitrary File Upload and RCE (Safe Check)");
  script_summary(english:"Checks the version of ManageEngine Desktop Central.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java web application that is affected
by remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of ManageEngine Desktop Central running on the remote host
is affected by the following file upload vulnerabilities that allow
the execution of arbitrary code by a remote attacker :

  - A failure to validate the 'filename' parameter of the
    'statusUpdate' servlet when performing a 'LFU' action.
    (CVE-2014-5005)

  - A failure to validate the 'filename' parameter of the
    'mdmLogUploader' servlet. (CVE-2014-5006)

  - A failure to validate the 'filename' parameter of the
    'agentLogUploader' servlet. This flaw was previously
    identified by CVE-2013-7390 and reported as fixed in
    version 8 build 80293; however, the fix was incomplete,
    and a method for bypassing it was discovered and
    re-reported. (CVE-2014-5007)");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-006/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2014/Aug/88");

  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine Desktop Central 9 build 90055 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"ManageEngine Desktop Central 8.0.0 File Upload");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'ManageEngine Desktop Central StatusUpdate Arbitrary File Upload');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:manageengine_desktop_central");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("manageengine_desktop_central_detect.nbin");
  script_require_ports("Services/www", 8020, 8383, 8040);
  script_require_keys("installed_sw/ManageEngine Desktop Central");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = "ManageEngine Desktop Central";
get_install_count(app_name:appname, exit_if_zero:TRUE);

port = get_http_port(default:8020);

install = get_single_install(
  app_name            : appname,
  port                : port,
  exit_if_unknown_ver : TRUE
);

dir = install["path"];
version = install["version"];
build   = install["build"];
ismsp   = install["MSP"];
rep_version = version;
if(build !=  UNKNOWN_VER)
  rep_version += " Build "+build;
install_url =  build_url(port:port, qs:dir);

# 7 - 9 build 90055
if (version !~ "^[7-9](\.|$)")
  audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url, rep_version);

if (version =~ "^9(\.|$)" && build == UNKNOWN_VER)
  exit(0, "The build number of "+appname+" version " +rep_version+ " listening at " +install_url+ " could not be determined.");

if (int(build) < 90055)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + rep_version +
      '\n  Fixed version     : 9 Build 90055' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url, rep_version);
