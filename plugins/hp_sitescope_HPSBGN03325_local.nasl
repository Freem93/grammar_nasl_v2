#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84089);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/21 22:04:46 $");

  script_cve_id("CVE-2015-2120");
  script_bugtraq_id(74801);
  script_xref(name:"HP",value:"emr_na-c04688784");
  script_xref(name:"IAVA", value:"2015-A-0126");
  script_xref(name:"HP",value:"HPSBGN03325");
  script_xref(name:"HP",value:"SSRT101902");

  script_name(english:"HP SiteScope Log Analysis Tool Remote Privilege Escalation (credentialed check)");
  script_summary(english:"Checks the version of HP SiteScope.");

  script_set_attribute(attribute:"synopsis",value:
"A web application installed on the remote host is affected by a
privilege escalation vulnerability.");
  script_set_attribute(attribute:"description",value:
"The HP SiteScope application installed on the remote host is affected
by a privilege escalation vulnerability due to a failure to restrict
the log path within the Log Analysis Tool. A remote, authenticated
attacker can exploit this flaw to read the 'users.config' file,
allowing an attacker to escalate privileges from the user to
administrator role.");
  script_set_attribute(attribute:"see_also",value:"http://www.zerodayinitiative.com/advisories/ZDI-15-239/");
  # https://h20566.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c04688784
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

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:hp:sitescope");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("hp_sitescope_installed.nbin");
  script_require_keys("installed_sw/HP SiteScope");
  script_require_ports("SMB/transport", 139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

appname = "HP SiteScope";

install = get_single_install(app_name:appname, exit_if_unknown_ver:TRUE);
version = install['version'];
build   = install['Build'];

path = install['path'];

if(isnull(build)) audit(AUDIT_VER_NOT_GRANULAR, appname, version + " Build " + build);

# extract numerical version string from build
# examples: SIS11.13.4
#           416
build_num = NULL;
item = eregmatch(pattern:"^[^\d.]*(\d[\d.]*)$", string:build);
build_num = item[1];

if(isnull(build_num))
  exit(1, "Unable to parse " + appname + " version build string : " + build);

# if build number is not a version string, tack it onto version
if("." >!< build_num) version += "." + build_num;

if (
  # no patches available for these
  (version =~ "^11\.1[0-2](\.|$)") ||
  (version =~ "^11\.2[0-3](\.|$)") ||
  # look for unpatched installs
  (version =~ "^11\.30(\.|$)" && ver_compare(ver:version, fix:'11.30.521.416', strict:FALSE)==-1) ||
  (version =~ "^11\.13(\.|$)" && ver_compare(ver:build, fix:'11.13.4', strict:FALSE)==-1) ||
  (version =~ "^11\.24(\.|#)" && ver_compare(ver:version, fix:'11.24.391.333', strict:FALSE)==-1))
{
  port = get_kb_item("SMB/transport");
  if(isnull(port)) port = 445;

  if (report_verbosity > 0)
  {
    fix = "11.13.4";
    if(version =~ "^11\.2")
      fix = "11.24 IP5";
    else if(version =~ "^11\.3")
      fix = "11.30 IP2";

    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);
