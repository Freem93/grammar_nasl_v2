#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-982.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(92992);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/13 14:37:13 $");

  script_cve_id("CVE-2016-3458", "CVE-2016-3485", "CVE-2016-3498", "CVE-2016-3500", "CVE-2016-3503", "CVE-2016-3508", "CVE-2016-3511", "CVE-2016-3550", "CVE-2016-3598", "CVE-2016-3606", "CVE-2016-3610");

  script_name(english:"openSUSE Security Update : OpenJDK7 (openSUSE-2016-982)");
  script_summary(english:"Check for the openSUSE-2016-982 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to 2.6.7 - OpenJDK 7u111

  - Security fixes

  - S8079718, CVE-2016-3458: IIOP Input Stream Hooking
    (bsc#989732)

  - S8145446, CVE-2016-3485: Perfect pipe placement (Windows
    only) (bsc#989734)

  - S8147771: Construction of static protection domains
    under Javax custom policy

  - S8148872, CVE-2016-3500: Complete name checking
    (bsc#989730)

  - S8149962, CVE-2016-3508: Better delineation of XML
    processing (bsc#989731)

  - S8150752: Share Class Data

  - S8151925: Font reference improvements

  - S8152479, CVE-2016-3550: Coded byte streams (bsc#989733)

  - S8155981, CVE-2016-3606: Bolster bytecode verification
    (bsc#989722)

  - S8155985, CVE-2016-3598: Persistent Parameter Processing
    (bsc#989723)

  - S8158571, CVE-2016-3610: Additional method handle
    validation (bsc#989725)

  - CVE-2016-3511 (bsc#989727)

  - CVE-2016-3503 (bsc#989728)

  - CVE-2016-3498 (bsc#989729)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=988651"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=989722"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=989723"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=989725"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=989727"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=989728"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=989729"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=989730"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=989731"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=989732"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=989733"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=989734"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected OpenJDK7 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-demo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-headless-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-1.7.0.111-24.39.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-accessibility-1.7.0.111-24.39.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-debuginfo-1.7.0.111-24.39.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-debugsource-1.7.0.111-24.39.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-demo-1.7.0.111-24.39.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-demo-debuginfo-1.7.0.111-24.39.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-devel-1.7.0.111-24.39.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-devel-debuginfo-1.7.0.111-24.39.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-headless-1.7.0.111-24.39.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-headless-debuginfo-1.7.0.111-24.39.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-javadoc-1.7.0.111-24.39.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-src-1.7.0.111-24.39.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_7_0-openjdk / java-1_7_0-openjdk-accessibility / etc");
}
