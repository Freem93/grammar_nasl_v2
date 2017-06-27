#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96610);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/04/21 16:53:28 $");

  script_cve_id("CVE-2017-3248");
  script_bugtraq_id(95465);
  script_osvdb_id(150444);
  script_xref(name:"TRA", value:"TRA-2017-07");
  script_xref(name:"ZDI", value:"ZDI-17-055");

  script_name(english:"Oracle WebLogic Server Java Object RMI Connect-Back Deserialization RCE (January 2017 CPU)");
  script_summary(english:"Checks for the patch.");

  script_set_attribute(attribute:"synopsis", value:
"An application server installed on the remote host is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle WebLogic Server installed on the remote host is
affected by a remote code execution vulnerability in the Core
Components subcomponent due to unsafe deserialization of Java objects
by the RMI registry. An unauthenticated, remote attacker can exploit
this, via a crafted Java object, to execute arbitrary Java code in the
context of the WebLogic server.");
  # http://www.oracle.com/technetwork/security-advisory/cpujan2017-2881727.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?89a8e429");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2017-07");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-055/");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2017 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:weblogic_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("oracle_weblogic_server_installed.nbin");
  script_require_keys("installed_sw/Oracle WebLogic Server");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "Oracle WebLogic Server";

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
ohome = install["Oracle Home"];
subdir = install["path"];
version = install["version"];

fix = NULL;
fix_ver = NULL;

# individual security patches
if (version =~ "^10\.3\.6\.")
{
  fix_ver = "10.3.6.0.170117";
  fix = "24667634";
}
else if (version =~ "^12\.1\.3\.")
{
  fix_ver = "12.1.3.0.170117";
  fix = "24904852";
}
else if (version =~ "^12\.2\.1\.0($|[^0-9])")
{
  fix_ver = "12.2.1.0.170117";
  fix = "24904865";
}
else if (version =~ "^12\.2\.1\.1($|[^0-9])")
{
  fix_ver = "12.2.1.1.170117";
  fix = "24907328";
}

if (!isnull(fix_ver) && ver_compare(ver:version, fix:fix_ver, strict:FALSE) == -1)
{
  port = 0;
  report =
    '\n  Oracle home    : ' + ohome +
    '\n  Install path   : ' + subdir +
    '\n  Version        : ' + version +
    '\n  Required patch : ' + fix +
    '\n';
  security_report_v4(extra:report, port:port, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, subdir);
