#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69195);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/21 22:04:46 $");

  script_cve_id("CVE-2013-2367", "CVE-2013-4835", "CVE-2013-6207");
  script_bugtraq_id(61506, 63478, 65972);
  script_osvdb_id(95824, 99230, 104020);

  script_name(english:"HP SiteScope Multiple Unspecified Remote Code Execution Vulnerabilities");
  script_summary(english:"Checks version of HP SiteScope");

  script_set_attribute(attribute:"synopsis", value:
"A web application installed on the remote host is affected by
multiple, unspecified code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of HP SiteScope installed on the remote host is potentially
affected by the following code execution vulnerabilities :

  - Unspecified errors exist related to SOAP functionality
    for which no further details have been provided.
    (CVE-2013-2367)

  - An error exists related to handling the SOAP command
    'issueSiebelCmd'. (CVE-2013-4835)

  - An error exists related to handling the SOAP command
    'loadFileContents'. (CVE-2013-6207)

By exploiting these flaws, a remote, unauthenticated attacker could
execute arbitrary code on the remote host subject to the privileges
of the user running the affected application.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-263/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-043/");
  # http://h20565.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c03861260-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a64e5c5e");
  # http://h20566.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c03969435-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1b244e28");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/531342/30/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP SiteScope 11.22 or later.

Alternatively, apply Cumulative Fixes SS1014131211 (for 10.14) /
SS1113131211 (for 11.13).");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"HP SiteScope runOMAgentCommand 11.20 RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'HP SiteScope issueSiebelCmd Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:sitescope");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("hp_sitescope_detect.nasl");
  script_require_keys("www/sitescope");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("webapp_func.inc");
include("http.inc");

port = get_http_port(default:8080);

install = get_install_from_kb(appname:'sitescope', port:port, exit_on_fail:TRUE);
version = install['ver'];
dir = install['dir'];

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, 'HP SiteScope', build_url(port:port, qs:dir));

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i < max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  (
    ver[0] == 10 &&
    (ver[1] < 14 || (report_paranoia == 2 && ver[1] == 14))
  ) ||
  (
    ver[0] == 11 &&
    (
      ver[1] < 13 ||
      (report_paranoia == 2 && ver[1] == 13) ||
      ver[1] == 20 ||
      ver[1] == 21
    )
  )
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + build_url(port:port, qs:dir) +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 10.14 with Cumulative Fixes SS1014131211 / 11.13 with SS1113131211 / 11.22\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, 'HP SiteScope',  build_url(port:port, qs:dir), version);
