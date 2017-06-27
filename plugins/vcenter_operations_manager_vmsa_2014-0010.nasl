#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78889);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/29 20:13:36 $");

  script_cve_id(
    "CVE-2014-6271",
    "CVE-2014-7169",
    "CVE-2014-7186",
    "CVE-2014-7187",
    "CVE-2014-6277",
    "CVE-2014-6278"
  );
  script_bugtraq_id(70103, 70137, 70152, 70154, 70165, 70166);
  script_osvdb_id(112004, 112096, 112097, 112158, 112169);
  script_xref(name:"CERT", value:"252743");
  script_xref(name:"IAVA", value:"2014-A-0142");
  script_xref(name:"EDB-ID", value:"34765");
  script_xref(name:"EDB-ID", value:"34766");
  script_xref(name:"EDB-ID", value:"34777");

  script_name(english:"VMware vCenter Operations Management Bash Vulnerabilities (VMSA-2014-0010) (Shellshock)");
  script_summary(english:"Checks the version of vCenter Operations Manager.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization appliance installed that is
affected by Shellshock.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCenter Operations Manager installed on the
remote host is prior to 5.7.3 / 5.8.3. It is, therefore, affected by
the environmental variable command injection vulnerability known as
'Shellshock'.");
  script_set_attribute(attribute:"see_also", value:"http://lists.vmware.com/pipermail/security-announce/2014/000272.html");
  # http://kb.vmware.com/selfservice/microsites/search.do?language=en_US&cmd=displayKC&externalId=2091083
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d5e08f66");
  # http://kb.vmware.com/selfservice/microsites/search.do?language=en_US&cmd=displayKC&externalId=2091002
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d4f0ad92");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2014-0010.html");
  script_set_attribute(attribute:"solution", value:"Apply the vendor supplied patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'CUPS Filter Bash Environment Variable Code Injection (Shellshock)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_operations");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl", "suse_11_bash-140926.nasl");
  script_require_keys("Host/VMware vCenter Operations Manager/Version", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/local_checks_enabled");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

# Check if general SuSE check already ran
if (get_kb_item("Success/77958"))  exit(0, "Plugin #77958 already found that bash needs to be updated.");

app = "VMware vCenter Operations Manager";
vuln = FALSE;

# local checks are required
get_kb_item_or_exit("Host/local_checks_enabled");

# Check that the host is SUSE
os = get_kb_item_or_exit("Host/SuSE/release");
if (os !~ "^SLES") audit(AUDIT_OS_NOT, "SuSE");

# rpm list is required
get_kb_item_or_exit("Host/SuSE/rpm-list");

# Make sure this is an affected version of vCOPs
# According to the advisory, vCOPS 5.x is vulnerable
# Software downloads and patches are only available
# for 5.7 and 5.8. We're checking for those specifically
version = get_kb_item_or_exit("Host/VMware vCenter Operations Manager/Version");
if (version !~ "^5\.[78]\.") audit(AUDIT_INST_VER_NOT_VULN, app, version);

# Perform RPM checks
if (rpm_check(release:"SLES11", sp:1, reference:"bash-3.2-147.14.22.1"))         vuln = TRUE;
if (rpm_check(release:"SLES11", sp:1, reference:"bash-doc-3.2-147.14.22.1"))     vuln = TRUE;
if (rpm_check(release:"SLES11", sp:1, reference:"libreadline5-5.2-147.14.22.1")) vuln = TRUE;
if (rpm_check(release:"SLES11", sp:1, reference:"readline-doc-5.2-147.14.22.1")) vuln = TRUE;
if (rpm_check(release:"SLES11", sp:1, reference:"libreadline5-32bit-5.2-147.14.22.1")) vuln = TRUE;

if (rpm_check(release:"SLES11", sp:2, reference:"bash-3.2-147.14.22.1"))         vuln = TRUE;
if (rpm_check(release:"SLES11", sp:2, reference:"bash-doc-3.2-147.14.22.1"))     vuln = TRUE;
if (rpm_check(release:"SLES11", sp:2, reference:"libreadline5-5.2-147.14.22.1")) vuln = TRUE;
if (rpm_check(release:"SLES11", sp:2, reference:"readline-doc-5.2-147.14.22.1")) vuln = TRUE;
if (rpm_check(release:"SLES11", sp:2, reference:"libreadline5-32bit-5.2-147.14.22.1")) vuln = TRUE;

if (rpm_check(release:"SLES11", sp:3, reference:"bash-3.2-147.22.1"))         vuln = TRUE;
if (rpm_check(release:"SLES11", sp:3, reference:"bash-doc-3.2-147.22.1"))     vuln = TRUE;
if (rpm_check(release:"SLES11", sp:3, reference:"libreadline5-5.2-147.22.1")) vuln = TRUE;
if (rpm_check(release:"SLES11", sp:3, reference:"readline-doc-5.2-147.22.1")) vuln = TRUE;
if (rpm_check(release:"SLES11", sp:3, reference:"libreadline5-32bit-5.2-147.22.1")) vuln = TRUE;


if (vuln)
{
  if (report_verbosity > 0)
  {
    report = '\n' + 'The remote ' + app + ' appliance has one or more outdated packages :' +
             '\n';
    security_hole(port:0, extra:report+rpm_report_get());
  }
  else security_hole(0);
}
else audit(AUDIT_HOST_NOT, "affected because the packages are up-to-date");
