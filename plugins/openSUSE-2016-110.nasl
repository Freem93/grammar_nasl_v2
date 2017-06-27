#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-110.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(88540);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/10/13 14:27:27 $");

  script_cve_id("CVE-2015-4871", "CVE-2015-7575", "CVE-2015-8126", "CVE-2015-8472", "CVE-2016-0402", "CVE-2016-0448", "CVE-2016-0466", "CVE-2016-0483", "CVE-2016-0494");

  script_name(english:"openSUSE Security Update : Java7 (openSUSE-2016-110) (SLOTH)");
  script_summary(english:"Check for the openSUSE-2016-110 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update OpenJDK to 7u95 / IcedTea 2.6.4 including the following fixes :

  - Security fixes

  - S8059054, CVE-2016-0402: Better URL processing

  - S8130710, CVE-2016-0448: Better attributes processing

  - S8132210: Reinforce JMX collector internals

  - S8132988: Better printing dialogues

  - S8133962, CVE-2016-0466: More general limits

  - S8137060: JMX memory management improvements

  - S8139012: Better font substitutions

  - S8139017, CVE-2016-0483: More stable image decoding

  - S8140543, CVE-2016-0494: Arrange font actions

  - S8143185: Cleanup for handling proxies

  - S8143941, CVE-2015-8126, CVE-2015-8472: Update
    splashscreen displays

  - S8144773, CVE-2015-7575: Further reduce use of MD5
    (SLOTH)

  - S8142882, CVE-2015-4871: rebinding of the receiver of a
    DirectMethodHandle may allow a protected method to be
    accessed

  - Import of OpenJDK 7 u95 build 0

  - S7167988: PKIX CertPathBuilder in reverse mode doesn't
    work if more than one trust anchor is specified

  - S8068761: [TEST_BUG]
    java/nio/channels/ServerSocketChannel/AdaptServerSocket.
    java failed with SocketTimeoutException

  - S8074068: Cleanup in
    src/share/classes/sun/security/x509/

  - S8075773: jps running as root fails after the fix of
    JDK-8050807

  - S8081297: SSL Problem with Tomcat

  - S8131181: Increment minor version of HSx for 7u95 and
    initialize the build number

  - S8132082: Let OracleUcrypto accept RSAPrivateKey

  - S8134605: Partial rework of the fix for 8081297

  - S8134861: XSLT: Extension func call cause exception if
    namespace URI contains partial package name

  - S8135307: CompletionFailure thrown when calling
    FieldDoc.type, if the field's type is missing

  - S8138716: (tz) Support tzdata2015g

  - S8140244: Port fix of JDK-8075773 to MacOSX

  - S8141213: [Parfait]Potentially blocking function
    GetArrayLength called in JNI critical region at line 239
    of jdk/src/share/native/sun/awt/image/jpeg/jpegdecoder.c
    in function GET_ARRAYS

  - S8141287: Add MD5 to jdk.certpath.disabledAlgorithms -
    Take 2

  - S8142928: [TEST_BUG]
    sun/security/provider/certpath/ReverseBuilder/ReverseBui
    ld.java 8u71 failure

  - S8143132: L10n resource file translation update

  - S8144955: Wrong changes were pushed with 8143942

  - S8145551: Test failed with Crash for Improved font
    lookups

  - S8147466: Add -fno-strict-overflow to
    IndicRearrangementProcessor{,2}.cpp

  - Backports

  - S8140244: Port fix of JDK-8075773 to AIX

  - S8133196, PR2712, RH1251935: HTTPS hostname invalid
    issue with InetAddress

  - S8140620, PR2710: Find and load default.sf2 as the
    default soundbank on Linux"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=939523"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=962743"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected Java7 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/27");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/03");
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

if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-1.7.0.95-24.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-accessibility-1.7.0.95-24.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-debuginfo-1.7.0.95-24.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-debugsource-1.7.0.95-24.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-demo-1.7.0.95-24.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-demo-debuginfo-1.7.0.95-24.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-devel-1.7.0.95-24.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-devel-debuginfo-1.7.0.95-24.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-headless-1.7.0.95-24.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-headless-debuginfo-1.7.0.95-24.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-javadoc-1.7.0.95-24.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-src-1.7.0.95-24.27.1") ) flag++;

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
