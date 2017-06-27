#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84088);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/21 22:04:46 $");

  script_cve_id("CVE-2015-2120");
  script_bugtraq_id(74801);
  script_xref(name:"HP",value:"emr_na-c04688784");
  script_xref(name:"IAVA", value:"2015-A-0126");
  script_xref(name:"HP",value:"HPSBGN03325");
  script_xref(name:"HP",value:"SSRT101902");

  script_name(english:"HP SiteScope Log Analysis Tool Remote Privilege Escalation (uncredentialed check)");
  script_summary(english:"Checks the version of HP SiteScope.");

  script_set_attribute(attribute:"synopsis",value:
"A web application running on the remote host is affected by a
privilege escalation vulnerability.");
  script_set_attribute(attribute:"description",value:
"The HP SiteScope application running on the remote host is affected by
a privilege escalation vulnerability due to a failure to restrict the
log path within the Log Analysis Tool. A remote, authenticated
attacker can exploit this flaw to read the 'users.config' file, 
allowing an attacker to escalate privileges from the user to
administrator role.");
  script_set_attribute(attribute:"see_also",value:"http://www.zerodayinitiative.com/advisories/ZDI-15-239/");
  # https://h20566.www2.hpe.com/portal/site/hpsc/public/kb/docDisplay/?docId=emr_na-c04688784
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?31c60b50");
  script_set_attribute(attribute:"solution",value:
"Apply the appropriate update according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/05/22");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/10");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:hp:sitescope");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("hp_sitescope_detect.nasl");
  script_require_keys("installed_sw/sitescope");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

appname = "sitescope";
# Stops get_http_port from branching
get_install_count(app_name:appname, exit_if_zero:TRUE);

port    = get_http_port(default:8080);
install = get_single_install(app_name:appname,port:port,exit_if_unknown_ver:TRUE);
version = install['version']; # Version level always at least Major.Minor.SP
url     = install['path'   ];
url     = build_url(port:port,qs:url);

if (
  (version =~ "^11\.1[0-2](\.|$)") ||
  (version =~ "^11\.2[0-3](\.|$)$") ||
  # 11.24/11.13/11.30 can be affected if they aren't patched
  (version == "11.30" && report_paranoia >= 2) ||
  (version == "11.24" && report_paranoia >= 2) ||
  (version == "11.13" && report_paranoia >= 2)
)
{
  if (report_verbosity > 0)
  {
    fix = "11.13.4";
    if(version =~ "^11\.2")
      fix = "11.24 IP5";
    else if(version =~ "^11\.3")
      fix = "11.30 IP2";

    report =
      '\n  URL               : ' + url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, url, version);
