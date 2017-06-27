#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-201.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(97002);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/02/06 15:09:25 $");

  script_cve_id("CVE-2016-2183", "CVE-2016-5546", "CVE-2016-5547", "CVE-2016-5548", "CVE-2016-5549", "CVE-2016-5552", "CVE-2017-3231", "CVE-2017-3241", "CVE-2017-3252", "CVE-2017-3253", "CVE-2017-3260", "CVE-2017-3261", "CVE-2017-3272", "CVE-2017-3289");

  script_name(english:"openSUSE Security Update : java-1_8_0-openjdk (openSUSE-2017-201)");
  script_summary(english:"Check for the openSUSE-2017-201 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for java-1_8_0-openjdk fixes the following issues: Oracle
Critical Patch Update of January 2017 (bsc#1020905) Upgrade to version
jdk8u121 (icedtea 3.3.0) :

  - S8138725: Add options for Javadoc generation

  - S8140353: Improve signature checking

  - S8151934, CVE-2017-3231: Resolve class resolution

  - S8156804, CVE-2017-3241: Better constraint checking

  - S8158406: Limited Parameter Processing

  - S8158997: JNDI Protocols Switch

  - S8159507: RuntimeVisibleAnnotation validation

  - S8161218: Better bytecode loading

  - S8161743, CVE-2017-3252: Provide proper login context

  - S8162577: Standardize logging levels

  - S8162973: Better component components

  - S8164143, CVE-2017-3260: Improve components for menu
    items

  - S8164147, CVE-2017-3261: Improve streaming socket output

  - S8165071, CVE-2016-2183: Expand TLS support

  - S8165344, CVE-2017-3272: Update concurrency support

  - S8166988, CVE-2017-3253: Improve image processing
    performance

  - S8167104, CVE-2017-3289: Additional class construction
    refinements

  - S8167223, CVE-2016-5552: URL handling improvements

  - S8168705, CVE-2016-5547: Better ObjectIdentifier
    validation

  - S8168714, CVE-2016-5546: Tighten ECDSA validation

  - S8168728, CVE-2016-5548: DSA signing improvements

  - S8168724, CVE-2016-5549: ECDSA signing improvements

This update was imported from the SUSE:SLE-12-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020905"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022053"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1_8_0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-demo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-headless-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.1|SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1 / 42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"java-1_8_0-openjdk-1.8.0.121-21.4") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_8_0-openjdk-accessibility-1.8.0.121-21.4") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.121-21.4") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_8_0-openjdk-debugsource-1.8.0.121-21.4") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_8_0-openjdk-demo-1.8.0.121-21.4") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_8_0-openjdk-demo-debuginfo-1.8.0.121-21.4") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_8_0-openjdk-devel-1.8.0.121-21.4") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_8_0-openjdk-devel-debuginfo-1.8.0.121-21.4") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_8_0-openjdk-headless-1.8.0.121-21.4") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.121-21.4") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_8_0-openjdk-javadoc-1.8.0.121-21.4") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_8_0-openjdk-src-1.8.0.121-21.4") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-1.8.0.121-6.4") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-accessibility-1.8.0.121-6.4") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.121-6.4") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-debugsource-1.8.0.121-6.4") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-demo-1.8.0.121-6.4") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-demo-debuginfo-1.8.0.121-6.4") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-devel-1.8.0.121-6.4") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-devel-debuginfo-1.8.0.121-6.4") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-headless-1.8.0.121-6.4") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.121-6.4") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-javadoc-1.8.0.121-6.4") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-src-1.8.0.121-6.4") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_8_0-openjdk / java-1_8_0-openjdk-accessibility / etc");
}
