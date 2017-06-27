#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-736.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(86962);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/11/20 15:06:53 $");

  script_cve_id("CVE-2015-4734", "CVE-2015-4803", "CVE-2015-4805", "CVE-2015-4806", "CVE-2015-4835", "CVE-2015-4840", "CVE-2015-4842", "CVE-2015-4843", "CVE-2015-4844", "CVE-2015-4860", "CVE-2015-4872", "CVE-2015-4881", "CVE-2015-4882", "CVE-2015-4883", "CVE-2015-4893", "CVE-2015-4903", "CVE-2015-4911");

  script_name(english:"openSUSE Security Update : java-1_7_0-openjdk (openSUSE-2015-736)");
  script_summary(english:"Check for the openSUSE-2015-736 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"java-1_7_0-openjdk was updated to version 7u91 to fix 17 security
issues.

These security issues were fixed :

  - CVE-2015-4843: Unspecified vulnerability in Oracle Java
    SE 6u101, 7u85, and 8u60, and Java SE Embedded 8u51,
    allowed remote attackers to affect confidentiality,
    integrity, and availability via unknown vectors related
    to Libraries (bsc#951376).

  - CVE-2015-4842: Unspecified vulnerability in Oracle Java
    SE 6u101, 7u85, and 8u60, and Java SE Embedded 8u51,
    allowed remote attackers to affect confidentiality via
    vectors related to JAXP (bsc#951376).

  - CVE-2015-4840: Unspecified vulnerability in Oracle Java
    SE 7u85 and 8u60, and Java SE Embedded 8u51, allowed
    remote attackers to affect confidentiality via unknown
    vectors related to 2D (bsc#951376).

  - CVE-2015-4872: Unspecified vulnerability in Oracle Java
    SE 6u101, 7u85, and 8u60; Java SE Embedded 8u51; and
    JRockit R28.3.7 allowed remote attackers to affect
    integrity via unknown vectors related to Security
    (bsc#951376).

  - CVE-2015-4860: Unspecified vulnerability in Oracle Java
    SE 6u101, 7u85, and 8u60, and Java SE Embedded 8u51,
    allowed remote attackers to affect confidentiality,
    integrity, and availability via vectors related to RMI,
    a different vulnerability than CVE-2015-4883
    (bsc#951376).

  - CVE-2015-4844: Unspecified vulnerability in Oracle Java
    SE 6u101, 7u85, and 8u60, and Java SE Embedded 8u51,
    allowed remote attackers to affect confidentiality,
    integrity, and availability via unknown vectors related
    to 2D (bsc#951376).

  - CVE-2015-4883: Unspecified vulnerability in Oracle Java
    SE 6u101, 7u85, and 8u60, and Java SE Embedded 8u51,
    allowed remote attackers to affect confidentiality,
    integrity, and availability via vectors related to RMI,
    a different vulnerability than CVE-2015-4860
    (bsc#951376).

  - CVE-2015-4893: Unspecified vulnerability in Oracle Java
    SE 6u101, 7u85, and 8u60; Java SE Embedded 8u51; and
    JRockit R28.3.7 allowed remote attackers to affect
    availability via vectors related to JAXP, a different
    vulnerability than CVE-2015-4803 and CVE-2015-4911
    (bsc#951376).

  - CVE-2015-4911: Unspecified vulnerability in Oracle Java
    SE 6u101, 7u85, and 8u60; Java SE Embedded 8u51; and
    JRockit R28.3.7 allowed remote attackers to affect
    availability via vectors related to JAXP, a different
    vulnerability than CVE-2015-4803 and CVE-2015-4893
    (bsc#951376).

  - CVE-2015-4882: Unspecified vulnerability in Oracle Java
    SE 6u101, 7u85, and 8u60, and Java SE Embedded 8u51,
    allowed remote attackers to affect availability via
    vectors related to CORBA (bsc#951376).

  - CVE-2015-4881: Unspecified vulnerability in Oracle Java
    SE 6u101, 7u85, and 8u60, and Java SE Embedded 8u51,
    allowed remote attackers to affect confidentiality,
    integrity, and availability via vectors related to
    CORBA, a different vulnerability than CVE-2015-4835
    (bsc#951376).

  - CVE-2015-4734: Unspecified vulnerability in Oracle Java
    SE 6u101, 7u85 and 8u60, and Java SE Embedded 8u51,
    allowed remote attackers to affect confidentiality via
    vectors related to JGSS (bsc#951376).

  - CVE-2015-4806: Unspecified vulnerability in Oracle Java
    SE 6u101, 7u85, and 8u60, and Java SE Embedded 8u51,
    allowed remote attackers to affect confidentiality and
    integrity via unknown vectors related to Libraries
    (bsc#951376).

  - CVE-2015-4805: Unspecified vulnerability in Oracle Java
    SE 6u101, 7u85, and 8u60, and Java SE Embedded 8u51,
    allowed remote attackers to affect confidentiality,
    integrity, and availability via unknown vectors related
    to Serialization (bsc#951376).

  - CVE-2015-4803: Unspecified vulnerability in Oracle Java
    SE 6u101, 7u85, and 8u60; Java SE Embedded 8u51; and
    JRockit R28.3.7 allowed remote attackers to affect
    availability via vectors related to JAXP, a different
    vulnerability than CVE-2015-4893 and CVE-2015-4911
    (bsc#951376).

  - CVE-2015-4835: Unspecified vulnerability in Oracle Java
    SE 6u101, 7u85, and 8u60, and Java SE Embedded 8u51,
    allowed remote attackers to affect confidentiality,
    integrity, and availability via vectors related to
    CORBA, a different vulnerability than CVE-2015-4881
    (bsc#951376).

  - CVE-2015-4903: Unspecified vulnerability in Oracle Java
    SE 6u101, 7u85, and 8u60, and Java SE Embedded 8u51,
    allowed remote attackers to affect confidentiality via
    vectors related to RMI (bsc#951376)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=951376"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1_7_0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-bootstrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-bootstrap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-bootstrap-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-bootstrap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-bootstrap-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-bootstrap-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-bootstrap-headless-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-1.7.0.91-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-accessibility-1.7.0.91-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-bootstrap-1.7.0.91-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-bootstrap-debuginfo-1.7.0.91-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-bootstrap-debugsource-1.7.0.91-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-bootstrap-devel-1.7.0.91-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-bootstrap-devel-debuginfo-1.7.0.91-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-bootstrap-headless-1.7.0.91-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-bootstrap-headless-debuginfo-1.7.0.91-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-debuginfo-1.7.0.91-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-debugsource-1.7.0.91-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-demo-1.7.0.91-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-demo-debuginfo-1.7.0.91-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-devel-1.7.0.91-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-devel-debuginfo-1.7.0.91-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-headless-1.7.0.91-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-headless-debuginfo-1.7.0.91-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-javadoc-1.7.0.91-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-src-1.7.0.91-22.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_7_0-openjdk-bootstrap / etc");
}
