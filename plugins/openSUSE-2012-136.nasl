#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-136.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74558);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/13 15:25:35 $");

  script_cve_id("CVE-2011-3563", "CVE-2011-3571", "CVE-2011-5035", "CVE-2012-0497", "CVE-2012-0501", "CVE-2012-0502", "CVE-2012-0503", "CVE-2012-0505", "CVE-2012-0506");

  script_name(english:"openSUSE Security Update : java-1_6_0-openjdk (openSUSE-2012-136)");
  script_summary(english:"Check for the openSUSE-2012-136 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"update to version 1.11.1 to fix several security issues :

  - S7082299, CVE-2011-3571: Fix in AtomicReferenceArray

  - S7088367, CVE-2011-3563: Fix issues in java sound

  - S7110683, CVE-2012-0502: Issues with some
    KeyboardFocusManager method

  - S7110687, CVE-2012-0503: Issues with TimeZone class

  - S7110700, CVE-2012-0505: Enhance exception throwing
    mechanism in ObjectStreamClass

  - S7110704, CVE-2012-0506: Issues with some method in
    corba

  - S7112642, CVE-2012-0497: Incorrect checking for graphics
    rendering object

  - S7118283, CVE-2012-0501: Better input parameter checking
    in zip file processing

  - S7126960, CVE-2011-5035: (httpserver) Add property to
    limit number of request headers to the HTTP Server"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=747208"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1_6_0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-demo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"java-1_6_0-openjdk-1.6.0.0_b24.1.11.1-3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"java-1_6_0-openjdk-debuginfo-1.6.0.0_b24.1.11.1-3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"java-1_6_0-openjdk-debugsource-1.6.0.0_b24.1.11.1-3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"java-1_6_0-openjdk-demo-1.6.0.0_b24.1.11.1-3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"java-1_6_0-openjdk-demo-debuginfo-1.6.0.0_b24.1.11.1-3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"java-1_6_0-openjdk-devel-1.6.0.0_b24.1.11.1-3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"java-1_6_0-openjdk-devel-debuginfo-1.6.0.0_b24.1.11.1-3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"java-1_6_0-openjdk-javadoc-1.6.0.0_b24.1.11.1-3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"java-1_6_0-openjdk-src-1.6.0.0_b24.1.11.1-3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_6_0-openjdk / java-1_6_0-openjdk-debuginfo / etc");
}
