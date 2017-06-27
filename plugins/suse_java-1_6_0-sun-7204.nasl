#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(51751);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/11/19 11:21:01 $");

  script_cve_id("CVE-2009-3555", "CVE-2010-1321", "CVE-2010-3541", "CVE-2010-3548", "CVE-2010-3549", "CVE-2010-3550", "CVE-2010-3551", "CVE-2010-3552", "CVE-2010-3553", "CVE-2010-3554", "CVE-2010-3555", "CVE-2010-3556", "CVE-2010-3557", "CVE-2010-3558", "CVE-2010-3559", "CVE-2010-3560", "CVE-2010-3561", "CVE-2010-3562", "CVE-2010-3563", "CVE-2010-3565", "CVE-2010-3566", "CVE-2010-3567", "CVE-2010-3568", "CVE-2010-3569", "CVE-2010-3570", "CVE-2010-3571", "CVE-2010-3572", "CVE-2010-3573", "CVE-2010-3574");

  script_name(english:"SuSE 10 Security Update : Sun Java 1.6.0 (ZYPP Patch Number 7204)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Sun Java 1.6.0 was updated to Security Update U22.

The release notes for this release are on:
http://www.oracle.com/technetwork/java/javase/6u22releasenotes-176121.
html

Security advisory page for this update:
http://www.oracle.com/technetwork/topics/security/javacpuoct2010-17625
8.html

Following CVEs are tracked for this update: CVE-2010-3556 /
CVE-2010-3562 / CVE-2010-3565 / CVE-2010-3566 / CVE-2010-3567 /
CVE-2010-3571 / CVE-2010-3554 / CVE-2010-3563 / CVE-2010-3568 /
CVE-2010-3569 / CVE-2010-3558 / CVE-2010-3552 / CVE-2010-3559 /
CVE-2010-3572 / CVE-2010-3553 / CVE-2010-3555 / CVE-2010-3550 /
CVE-2010-3570 / CVE-2010-3561 / CVE-2009-3555 / CVE-2010-1321 /
CVE-2010-3549 / CVE-2010-3557 / CVE-2010-3541 / CVE-2010-3573 /
CVE-2010-3574 / CVE-2010-3548 / CVE-2010-3551 / CVE-2010-3560"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3555.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1321.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3541.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3548.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3549.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3550.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3551.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3552.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3553.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3554.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3555.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3556.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3557.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3558.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3559.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3560.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3561.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3562.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3563.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3565.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3566.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3567.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3568.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3569.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3570.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3571.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3572.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3573.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3574.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7204.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java Web Start BasicServiceImpl Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLED10", sp:3, reference:"java-1_6_0-sun-1.6.0.u22-1.8.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"java-1_6_0-sun-alsa-1.6.0.u22-1.8.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"java-1_6_0-sun-demo-1.6.0.u22-1.8.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"java-1_6_0-sun-jdbc-1.6.0.u22-1.8.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"java-1_6_0-sun-src-1.6.0.u22-1.8.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"i586", reference:"java-1_6_0-sun-plugin-1.6.0.u22-1.8.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"java-1_6_0-sun-32bit-1.6.0.u22-1.8.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"java-1_6_0-sun-plugin-32bit-1.6.0.u22-1.8.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
