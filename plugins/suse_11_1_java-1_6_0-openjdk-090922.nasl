#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update java-1_6_0-openjdk-1330.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(41623);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/21 20:09:51 $");

  script_cve_id("CVE-2009-2475", "CVE-2009-2476", "CVE-2009-2625", "CVE-2009-2670", "CVE-2009-2671", "CVE-2009-2672", "CVE-2009-2673", "CVE-2009-2674", "CVE-2009-2675", "CVE-2009-2689", "CVE-2009-2690");

  script_name(english:"openSUSE Security Update : java-1_6_0-openjdk (java-1_6_0-openjdk-1330)");
  script_summary(english:"Check for the java-1_6_0-openjdk-1330 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of java-1_6_0-openjdk fixes the following issues :

  - CVE-2009-2670: OpenJDK Untrusted applet System
    properties access

  - CVE-2009-2671,CVE-2009-2672: OpenJDK Proxy mechanism
    information leaks

  - CVE-2009-2673: OpenJDK proxy mechanism allows
    non-authorized socket connections

  - CVE-2009-2674: Java Web Start Buffer JPEG processing
    integer overflow

  - CVE-2009-2675: Java Web Start Buffer unpack200
    processing integer overflow

  - CVE-2009-2625: OpenJDK XML parsing Denial-Of-Service

  - CVE-2009-2475: OpenJDK information leaks in mutable
    variables

  - CVE-2009-2476: OpenJDK OpenType checks can be bypassed

  - CVE-2009-2689: OpenJDK JDK13Services grants unnecessary
    privileges

  - CVE-2009-2690: OpenJDK private variable information
    disclosure"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=537969"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1_6_0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(200, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.1", reference:"java-1_6_0-openjdk-1.6_b16-0.1.3") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"java-1_6_0-openjdk-demo-1.6_b16-0.1.3") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"java-1_6_0-openjdk-devel-1.6_b16-0.1.3") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"java-1_6_0-openjdk-javadoc-1.6_b16-0.1.3") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"java-1_6_0-openjdk-plugin-1.6_b16-0.1.3") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"java-1_6_0-openjdk-src-1.6_b16-0.1.3") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_6_0-openjdk");
}
