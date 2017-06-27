#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update java-1_6_0-sun-3354.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75540);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:55:23 $");

  script_cve_id("CVE-2009-3555", "CVE-2010-1321", "CVE-2010-3541", "CVE-2010-3548", "CVE-2010-3549", "CVE-2010-3550", "CVE-2010-3551", "CVE-2010-3552", "CVE-2010-3553", "CVE-2010-3554", "CVE-2010-3555", "CVE-2010-3556", "CVE-2010-3557", "CVE-2010-3558", "CVE-2010-3559", "CVE-2010-3560", "CVE-2010-3561", "CVE-2010-3562", "CVE-2010-3563", "CVE-2010-3565", "CVE-2010-3566", "CVE-2010-3567", "CVE-2010-3568", "CVE-2010-3569", "CVE-2010-3570", "CVE-2010-3571", "CVE-2010-3572", "CVE-2010-3573", "CVE-2010-3574");

  script_name(english:"openSUSE Security Update : java-1_6_0-sun (openSUSE-SU-2010:0754-1)");
  script_summary(english:"Check for the java-1_6_0-sun-3354 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
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

Following CVEs are tracked by the update: CVE-2010-3556 CVE-2010-3562
CVE-2010-3565 CVE-2010-3566 CVE-2010-3567 CVE-2010-3571 CVE-2010-3554
CVE-2010-3563 CVE-2010-3568 CVE-2010-3569 CVE-2010-3558 CVE-2010-3552
CVE-2010-3559 CVE-2010-3572 CVE-2010-3553 CVE-2010-3555 CVE-2010-3550
CVE-2010-3570 CVE-2010-3561 CVE-2009-3555 CVE-2010-1321 CVE-2010-3549
CVE-2010-3557 CVE-2010-3541 CVE-2010-3573 CVE-2010-3574 CVE-2010-3548
CVE-2010-3551 CVE-2010-3560"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2010-10/msg00026.html"
  );
  # http://www.oracle.com/technetwork/java/javase/6u22releasenotes-176121.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ec585d60"
  );
  # http://www.oracle.com/technetwork/topics/security/javacpuoct2010-176258.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bc96963b"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=646073"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1_6_0-sun packages."
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-sun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-sun-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-sun-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-sun-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-sun-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-sun-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE11\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.3", reference:"java-1_6_0-sun-1.6.0.u22-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"java-1_6_0-sun-alsa-1.6.0.u22-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"java-1_6_0-sun-devel-1.6.0.u22-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"java-1_6_0-sun-jdbc-1.6.0.u22-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"java-1_6_0-sun-plugin-1.6.0.u22-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"java-1_6_0-sun-src-1.6.0.u22-1.2.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_6_0-sun");
}
