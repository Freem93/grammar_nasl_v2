#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78857);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2017/04/25 20:29:05 $");

  script_cve_id(
    "CVE-2014-6271",
    "CVE-2014-6277",
    "CVE-2014-6278",
    "CVE-2014-7169",
    "CVE-2014-7186",
    "CVE-2014-7187"
  );
  script_bugtraq_id(70103, 70137, 70152, 70154, 70165, 70166);
  script_osvdb_id(112004, 112096, 112097, 112158, 112169);
  script_xref(name:"VMSA", value:"2014-0010");
  script_xref(name:"IAVA", value:"2014-A-0142");
  script_xref(name:"CERT", value:"252743");
  script_xref(name:"EDB-ID", value:"34765");
  script_xref(name:"EDB-ID", value:"34766");
  script_xref(name:"EDB-ID", value:"34777");

  script_name(english:"VMware Workspace Portal Multiple Bash Shell Vulnerabilities (VMSA-2014-0010) (Shellshock)");
  script_summary(english:"Checks the version of VMware Workspace Portal.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a device management application installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Workspace Portal (formerly known as VMware
Horizon Workspace) installed on the remote host is missing package
updates. It is, therefore, affected by the following vulnerabilities
in the Bash shell :

  - A command injection vulnerability exists in GNU Bash
    known as Shellshock, which is due to the processing of
    trailing strings after function definitions in the
    values of environment variables. This allows a remote
    attacker to execute arbitrary code via environment
    variable manipulation depending on the configuration of
    the system. By sending a specially crafted request to a
    CGI script that passes environment variables, a remote,
    unauthenticated attacker can execute arbitrary code on
    the host. (CVE-2014-6271, CVE-2014-6277, CVE-2014-6278,
    CVE-2014-7169)

  - An out-of-bounds memory access error exists due to
    improper redirection implementation in the 'parse.y'
    source file. A remote attacker can exploit this issue
    to cause a denial of service or potentially execute
    arbitrary code. (CVE-2014-7186)

  - An off-by-one error exists in the 'read_token_word'
    function in the 'parse.y' source file. A remote attacker
    can exploit this issue to cause a denial of service or
    potentially execute arbitrary code. (CVE-2014-7187)");
  script_set_attribute(attribute:"see_also", value:"http://kb.vmware.com/kb/2091067");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2014-0010");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2014/q3/650");
  script_set_attribute(attribute:"see_also", value:"https://www.invisiblethreat.ca/post/shellshock/");

  script_set_attribute(attribute:"solution", value:"Apply the relevant patch as stated in the 2091067 VMware KB advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'CUPS Filter Bash Environment Variable Code Injection (Shellshock)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/04");

  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:vmware:vmware_horizon_workspace");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:vmware:vmware_workspace_portal");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl", "suse_11_bash-140926.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list");
  script_require_ports("Host/VMware Horizon Workspace/Version", "Host/VMware Workspace Portal/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

# Check if general SuSE check already ran
if (get_kb_item("Success/77958"))  exit(0, "Plugin #77958 already found that bash needs to be updated.");

# Check that the OS is SuSE
if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^SLES") audit(AUDIT_OS_NOT, "SuSE");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

app     = NULL;
version = NULL;

version = get_kb_item("Host/VMware Horizon Workspace/Version");
if (!isnull(version))
{
  app = "VMware Horizon Workspace";
}
else
{
  version = get_kb_item("Host/VMware Workspace Portal/Version");
  app = "VMware Workspace Portal";
}

if (isnull(version)) audit(AUDIT_NOT_INST, "VMware Horizon Workspace / VMware Workspace Portal");

# VMware Horizon Workspace affected versions:
#   1.5.0 - 1.5.2
#   1.8.0 - 1.8.2
if (app == "VMware Horizon Workspace" && version !~ "^1\.[58]\.[0-2]$")
  audit(AUDIT_INST_VER_NOT_VULN, app, version);
# VMware Workspace Portal affected versions:
#   2.0.0 and 2.1.0
else if (app == "VMware Workspace Portal" && version !~ "^2\.[01]\.0$")
  audit(AUDIT_INST_VER_NOT_VULN, app, version);

vuln = FALSE;
if (rpm_check(release:"SLES11", sp:2, reference:"bash-3.2-147.14.22.1"))               vuln = TRUE;
if (rpm_check(release:"SLES11", sp:2, reference:"bash-doc-3.2-147.14.22.1"))           vuln = TRUE;
if (rpm_check(release:"SLES11", sp:2, reference:"libreadline5-5.2-147.14.22.1"))       vuln = TRUE;
if (rpm_check(release:"SLES11", sp:2, reference:"libreadline5-32bit-5.2-147.14.22.1")) vuln = TRUE;
if (rpm_check(release:"SLES11", sp:2, reference:"readline-doc-5.2-147.14.22.1"))       vuln = TRUE;

if (rpm_check(release:"SLES11", sp:3, reference:"bash-3.2-147.22.1"))               vuln = TRUE;
if (rpm_check(release:"SLES11", sp:3, reference:"bash-doc-3.2-147.22.1"))           vuln = TRUE;
if (rpm_check(release:"SLES11", sp:3, reference:"libreadline5-5.2-147.22.1"))       vuln = TRUE;
if (rpm_check(release:"SLES11", sp:3, reference:"libreadline5-32bit-5.2-147.22.1")) vuln = TRUE;
if (rpm_check(release:"SLES11", sp:3, reference:"readline-doc-5.2-147.22.1"))       vuln = TRUE;

if (!vuln)  audit(AUDIT_HOST_NOT, "affected because the packages are up-to-date");


if (report_verbosity > 0)
{
  report = '\n' + 'The remote ' + app + ' appliance has one or more outdated packages :' +
           '\n' +
           rpm_report_get();
  security_hole(port:0, extra:report);
}
else security_hole(0);
