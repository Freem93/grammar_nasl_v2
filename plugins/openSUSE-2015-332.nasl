#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-332.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(83107);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/04/28 13:21:36 $");

  script_cve_id("CVE-2015-0458", "CVE-2015-0459", "CVE-2015-0460", "CVE-2015-0469", "CVE-2015-0470", "CVE-2015-0477", "CVE-2015-0478", "CVE-2015-0480", "CVE-2015-0484", "CVE-2015-0486", "CVE-2015-0488", "CVE-2015-0491", "CVE-2015-0492");

  script_name(english:"openSUSE Security Update : java-1_8_0-openjdk (openSUSE-2015-332)");
  script_summary(english:"Check for the openSUSE-2015-332 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"OpenJDK was updated to jdk8u45-b14 to fix security issues and bugs.

The following vulnerabilities were fixed :

  - CVE-2015-0458: Deployment: unauthenticated remote
    attackers could execute arbitrary code via multiple
    protocols.

  - CVE-2015-0459: 2D: unauthenticated remote attackers
    could execute arbitrary code via multiple protocols.

  - CVE-2015-0460: Hotspot: unauthenticated remote attackers
    could execute arbitrary code via multiple protocols.

  - CVE-2015-0469: 2D: unauthenticated remote attackers
    could execute arbitrary code via multiple protocols.

  - CVE-2015-0470: Hotspot: unauthenticated remote attackers
    could update, insert or delete some JAVA accessible data
    via multiple protocols

  - CVE-2015-0477: Beans: unauthenticated remote attackers
    could update, insert or delete some JAVA accessible data
    via multiple protocols

  - CVE-2015-0478: JCE: unauthenticated remote attackers
    could read some JAVA accessible data via multiple
    protocols

  - CVE-2015-0480: Tools: unauthenticated remote attackers
    could update, insert or delete some JAVA accessible data
    via multiple protocols and cause a partial denial of
    service (partial DOS)

  - CVE-2015-0484: JavaFX: unauthenticated remote attackers
    could read, update, insert or delete access some Java
    accessible data via multiple protocols and cause a
    partial denial of service (partial DOS).

  - CVE-2015-0486: Deployment: unauthenticated remote
    attackers could read some JAVA accessible data via
    multiple protocols

  - CVE-2015-0488: JSSE: unauthenticated remote attackers
    could cause a partial denial of service (partial DOS).

  - CVE-2015-0491: 2D: unauthenticated remote attackers
    could execute arbitrary code via multiple protocols.

  - CVE-2015-0492: JavaFX: unauthenticated remote attackers
    could execute arbitrary code via multiple protocols."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=927591"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1_8_0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-demo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-headless-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/28");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"java-1_8_0-openjdk-1.8.0.45-9.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_8_0-openjdk-accessibility-1.8.0.45-9.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.45-9.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_8_0-openjdk-debugsource-1.8.0.45-9.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_8_0-openjdk-demo-1.8.0.45-9.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_8_0-openjdk-demo-debuginfo-1.8.0.45-9.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_8_0-openjdk-devel-1.8.0.45-9.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_8_0-openjdk-headless-1.8.0.45-9.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.45-9.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_8_0-openjdk-javadoc-1.8.0.45-9.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_8_0-openjdk-src-1.8.0.45-9.3") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_8_0-openjdk / java-1_8_0-openjdk-accessibility / etc");
}
