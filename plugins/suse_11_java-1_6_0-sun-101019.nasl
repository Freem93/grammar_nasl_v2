#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(50919);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/11/19 11:21:01 $");

  script_cve_id("CVE-2009-3555", "CVE-2010-1321", "CVE-2010-3541", "CVE-2010-3548", "CVE-2010-3549", "CVE-2010-3550", "CVE-2010-3551", "CVE-2010-3552", "CVE-2010-3553", "CVE-2010-3554", "CVE-2010-3555", "CVE-2010-3556", "CVE-2010-3557", "CVE-2010-3558", "CVE-2010-3559", "CVE-2010-3560", "CVE-2010-3561", "CVE-2010-3562", "CVE-2010-3563", "CVE-2010-3565", "CVE-2010-3566", "CVE-2010-3567", "CVE-2010-3568", "CVE-2010-3569", "CVE-2010-3570", "CVE-2010-3571", "CVE-2010-3572", "CVE-2010-3573", "CVE-2010-3574");

  script_name(english:"SuSE 11 / 11.1 Security Update : Java 1.6.0 (SAT Patch Numbers 3347 / 3349)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
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
8.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=646073"
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
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 3347 / 3349 as appropriate."
  );
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-sun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-sun-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-sun-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-sun-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-sun-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-sun-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);


flag = 0;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"java-1_6_0-sun-1.6.0.u22-1.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"java-1_6_0-sun-alsa-1.6.0.u22-1.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"java-1_6_0-sun-demo-1.6.0.u22-1.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"java-1_6_0-sun-jdbc-1.6.0.u22-1.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"java-1_6_0-sun-plugin-1.6.0.u22-1.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"java-1_6_0-sun-src-1.6.0.u22-1.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"java-1_6_0-sun-1.6.0.u22-1.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"java-1_6_0-sun-alsa-1.6.0.u22-1.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"java-1_6_0-sun-demo-1.6.0.u22-1.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"java-1_6_0-sun-jdbc-1.6.0.u22-1.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"java-1_6_0-sun-plugin-1.6.0.u22-1.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"java-1_6_0-sun-src-1.6.0.u22-1.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"java-1_6_0-sun-1.6.0.u22-1.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"java-1_6_0-sun-alsa-1.6.0.u22-1.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"java-1_6_0-sun-demo-1.6.0.u22-1.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"java-1_6_0-sun-jdbc-1.6.0.u22-1.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"java-1_6_0-sun-plugin-1.6.0.u22-1.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"java-1_6_0-sun-src-1.6.0.u22-1.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"java-1_6_0-sun-1.6.0.u22-1.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"java-1_6_0-sun-alsa-1.6.0.u22-1.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"java-1_6_0-sun-demo-1.6.0.u22-1.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"java-1_6_0-sun-jdbc-1.6.0.u22-1.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"java-1_6_0-sun-plugin-1.6.0.u22-1.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"java-1_6_0-sun-src-1.6.0.u22-1.2.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
