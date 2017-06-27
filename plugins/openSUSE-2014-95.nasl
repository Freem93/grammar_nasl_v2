#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-95.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75413);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/10/28 10:42:46 $");

  script_cve_id("CVE-2013-5878", "CVE-2013-5884", "CVE-2013-5893", "CVE-2013-5896", "CVE-2013-5907", "CVE-2013-5910", "CVE-2014-0368", "CVE-2014-0373", "CVE-2014-0376", "CVE-2014-0408", "CVE-2014-0411", "CVE-2014-0416", "CVE-2014-0422", "CVE-2014-0423", "CVE-2014-0428");

  script_name(english:"openSUSE Security Update : java-1_7_0-openjdk (openSUSE-SU-2014:0174-1)");
  script_summary(english:"Check for the openSUSE-2014-95 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Fix a file conflict between -devel and -headless package 

  - Update to 2.4.4 (bnc#858818)

  - changed from xz to gzipped tarball as the first was not
    available during update

  - changed a keyring file due release manager change new
    one is signed by 66484681 from omajid@redhat.com, see
    http://mail.openjdk.java.net/pipermail/distro-pkg-dev/20
    14-January/025800.html

  - Security fixes

  - S6727821: Enhance JAAS Configuration

  - S7068126, CVE-2014-0373: Enhance SNMP statuses

  - S8010935: Better XML handling

  - S8011786, CVE-2014-0368: Better applet networking

  - S8021257, S8025022, CVE-2013-5896 : com.sun.corba.se.**
    should be on restricted package list

  - S8021271, S8021266, CVE-2014-0408: Better buffering in
    ObjC code

  - S8022904: Enhance JDBC Parsers

  - S8022927: Input validation for byte/endian conversions

  - S8022935: Enhance Apache resolver classes

  - S8022945: Enhance JNDI implementation classes

  - S8023057: Enhance start up image display

  - S8023069, CVE-2014-0411: Enhance TLS connections

  - S8023245, CVE-2014-0423: Enhance Beans decoding

  - S8023301: Enhance generic classes

  - S8023338: Update jarsigner to encourage timestamping

  - S8023672: Enhance jar file validation

  - S8024302: Clarify jar verifications

  - S8024306, CVE-2014-0416: Enhance Subject consistency

  - S8024530: Enhance font process resilience

  - S8024867: Enhance logging start up

  - S8025014: Enhance Security Policy

  - S8025018, CVE-2014-0376: Enhance JAX-P set up

  - S8025026, CVE-2013-5878: Enhance canonicalization

  - S8025034, CVE-2013-5907: Improve layout lookups

  - S8025448: Enhance listening events

  - S8025758, CVE-2014-0422: Enhance Naming management

  - S8025767, CVE-2014-0428: Enhance IIOP Streams

  - S8026172: Enhance UI Management

  - S8026176: Enhance document printing

  - S8026193, CVE-2013-5884: Enhance CORBA stub factories

  - S8026204: Enhance auth login contexts

  - S8026417, CVE-2013-5910: Enhance XML canonicalization

  - S8026502: java/lang/invoke/MethodHandleConstants.java
    fails on all platforms

  - S8027201, CVE-2014-0376: Enhance JAX-P set up

  - S8029507, CVE-2013-5893: Enhance JVM method processing

  - S8029533: REGRESSION:
    closed/java/lang/invoke/8008140/Test8008140.java fails
    against

  - Backports

  - S8025255: (tz) Support tzdata2013g

  - S8026826: JDK 7 fix for 8010935 broke the build

  - Bug fixes

  - PR1618: Include defs.make in vm.make so VM_LITTLE_ENDIAN
    is defined on Zero builds

  - D729448: 32-bit alignment on mips and mipsel

  - PR1623: Collision between OpenJDK 6 & 7 classes when
    bootstrapping with OpenJDK 6

  - Add update.py, helper script to download openjdk
    tarballs from hg repo

  - Buildrequire quilt unconditionally as it's used
    unconditionally.

  - Really disable tests on non-JIT architectures. (from
    Ulrich Weigand)

  - Add headless subpackage wich does not require X and
    pulse/alsa

  - Add accessibility to extra subpackage, which requires
    new java-atk-wrapper package

  - removed java-1.7.0-openjdk-java-access-bridge-idlj.patch

  - removed java-1.7.0-openjdk-java-access-bridge-tck.patch

  - removed java-access-bridge-1.26.2.tar.bz2

  - Refreshed

  - java-1.7.0-openjdk-java-access-bridge-security.patch

  - Add a support for running tests using --with tests

  - this is ignored on non-jit architectures

  - Prefer global over define as bcond_with does use them

  - Forward declare aarch64 arch macro

  - Define archbuild/archinstall macros for arm and aarch64

  - remove a few ifarch conditions by using those macros in
    filelist

  - Need ecj-bootstrap in bootstrap mode (noted by mmatz)

  - Don't install vim and quilt in bootstrap mode

  - A few enhancenments of bootstrap mode

  - usable wia --with bootstrap

  - disable docs, javadoc package

  - fix configure arguments on bootstrap

  - Add the unversioned SDK directory link to the files list
    of -devel package (fixes update-alternatives from
    %post).

  - Add support for bootstrapping with just gcj (using
    included ecj directly). Increase stacksize for powerpc
    (amends java-1.7.0-openjdk-ppc-zero-jdk.patch). Add
    support for ppc64le.

  - fix stackoverflow for powerpc
    (java-1_7_0-openjdk-ppc-stackoverflow.patch)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-01/msg00105.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-01/msg00107.html"
  );
  # http://mail.openjdk.java.net/pipermail/distro-pkg-dev/2014-January/025800.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3c8576e2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=858818"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1_7_0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/22");
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
if (release !~ "^(SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-1.7.0.6-24.13.5") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-accessibility-1.7.0.6-24.13.5") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-debuginfo-1.7.0.6-24.13.5") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-debugsource-1.7.0.6-24.13.5") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-demo-1.7.0.6-24.13.5") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-demo-debuginfo-1.7.0.6-24.13.5") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-devel-1.7.0.6-24.13.5") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-devel-debuginfo-1.7.0.6-24.13.5") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-headless-1.7.0.6-24.13.5") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-headless-debuginfo-1.7.0.6-24.13.5") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-javadoc-1.7.0.6-24.13.5") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-src-1.7.0.6-24.13.5") ) flag++;

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
