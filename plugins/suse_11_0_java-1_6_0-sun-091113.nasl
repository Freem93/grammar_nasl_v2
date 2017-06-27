#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update java-1_6_0-sun-1541.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(42851);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/21 20:09:50 $");

  script_cve_id("CVE-2009-3864", "CVE-2009-3865", "CVE-2009-3866", "CVE-2009-3867", "CVE-2009-3868", "CVE-2009-3869", "CVE-2009-3871", "CVE-2009-3872", "CVE-2009-3873", "CVE-2009-3874", "CVE-2009-3875", "CVE-2009-3876", "CVE-2009-3877");

  script_name(english:"openSUSE Security Update : java-1_6_0-sun (java-1_6_0-sun-1541)");
  script_summary(english:"Check for the java-1_6_0-sun-1541 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Sun Java 6 SDK/JRE was updated to u17 update fixing bugs and
various security issues :

CVE-2009-3866:The Java Web Start Installer in Sun Java SE in JDK and
JRE 6 before Update 17 does not properly use security model
permissions when removing installer extensions, which allows remote
attackers to execute arbitrary code by modifying a certain JNLP file
to have a URL field that poi nts to an unintended trusted application,
aka Bug Id 6872824.

CVE-2009-3867: Stack-based buffer overflow in the
HsbParser.getSoundBank function in Sun Java SE in JDK and JRE 5.0
before Update 22, JDK and JRE 6 before Update 17, SDK and JRE 1.3.x
before 1.3.1_27, and SDK and JRE 1.4.x before 1.4.2_24 allows remote
attackers to execute arbitrary code via a long file: URL in an
argument, aka Bug Id 6854303.

CVE-2009-3869: Stack-based buffer overflow in the setDiffICM function
in the Abstract Window Toolkit (AWT) in Java Runtime Environment (JRE)
in Sun Java SE in JDK and JRE 5.0 before Update 22, JDK and JRE 6
before Update 17, SDK and JRE 1.3.x before 1.3.1_27, and SDK and JRE
1.4.x before 1.4.2_ 24 allows remote attackers to execute arbitrary
code via a crafted argument, aka Bug Id 6872357.

CVE-2009-3871: Heap-based buffer overflow in the setBytePixels
function in the Abstract Window Toolkit (AWT) in Java Runtime
Environment (JRE) in Sun Java SE in JDK and JRE 5.0 before Update 22,
JDK and JRE 6 before Update 17, SDK and JRE 1.3.x before 1.3.1_27, and
SDK and JRE 1.4.x before 1.4. 2_24 allows remote attackers to execute
arbitrary code via crafted arguments, aka Bug Id 6872358.

CVE-2009-3874: Integer overflow in the JPEGImageReader implementation
in the ImageI/O component in Sun Java SE in JDK and JRE 5.0 before
Update 22, JDK and JRE 6 before Update 17, and SDK and JRE 1.4.x
before 1.4.2_24 allows remote attackers to execute arbitrary code via
large subsample dimensi ons in a JPEG file that triggers a heap-based
buffer overflow, aka Bug Id 6874643.

CVE-2009-3875: The MessageDigest.isEqual function in Java Runtime
Environment (JRE) in Sun Java SE in JDK and JRE 5.0 before Update 22,
JDK and JRE 6 before Update 17, SDK and JRE 1.3.x before 1.3.1_27, and
SDK and JRE 1.4.x before 1.4.2_24 allows remote attackers to spoof
HMAC-based digital si gnatures, and possibly bypass authentication,
via unspecified vectors related to 'timing attack vulnerabilities,'
aka Bug Id 6863503.

CVE-2009-3876: Unspecified vulnerability in Sun Java SE in JDK and JRE
5.0 before Update 22, JDK and JRE 6 before Update 17, SDK and JRE
1.3.x before 1.3.1 _27, and SDK and JRE 1.4.x before 1.4.2_24 allows
remote attackers to cause a denial of service (memory consumption) via
crafted DER encoded data, which is not properly decoded by the ASN.1
DER input stream parser, aka Bug Id 6864911.

CVE-2009-3877: Unspecified vulnerability in Sun Java SE in JDK and JRE
5.0 before Update 22, JDK and JRE 6 before Update 17, SDK and JRE
1.3.x before 1.3.1 _27, and SDK and JRE 1.4.x before 1.4.2_24 allows
remote attackers to cause a denial of service (memory consumption) via
crafted HTTP header s, which are not properly parsed by the ASN.1 DER
input stream parser, aka Bug Id 6864911.

CVE-2009-3864: The Java Update functionality in Java Runtime
Environment (JRE) in Sun Java SE in JDK and JRE 5.0 before Update 22
and JDK and JRE 6 before Update 17, when a non-English version of
Windows is used, does not retrieve available new JRE versions, which
allows remote attackers to lev erage vulnerabilities in older releases
of this software, aka Bug Id 6869694.

CVE-2009-3865: The launch method in the Deployment Toolkit plugin in
Java Runtime Environment (JRE) in Sun Java SE in JDK and JRE 6 before
Update 17 allows remote attackers to execute arbitrary commands via a
crafted web page, aka Bug Id 6869752.

CVE-2009-3868: Sun Java SE in JDK and JRE 5.0 before Update 22, JDK
and JRE 6 before Update 17, SDK and JRE 1.3.x before 1.3.1_27, and SDK
and JRE 1.4.x be fore 1.4.2_24 does not properly parse color profiles,
which allows remote attackers to gain privileges via a crafted image
file, aka Bug Id 6862970.

CVE-2009-3872: Unspecified vulnerability in the JPEG JFIF Decoder in
Sun Java SE in JDK and JRE 5.0 before Update 22, JDK and JRE 6 before
Update 17, SDK a nd JRE 1.3.x before 1.3.1_27, and SDK and JRE 1.4.x
before 1.4.2_24 allows remote attackers to gain privileges via a
crafted image file, aka Bug Id 6862969.

CVE-2009-3873: The JPEG Image Writer in Sun Java SE in JDK and JRE 5.0
before Update 22, JDK and JRE 6 before Update 17, and SDK and JRE
1.4.x before 1.4.2 _24 allows remote attackers to gain privileges via
a crafted image file, related to a 'quanization problem,' aka Bug Id
6862968."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=552586"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1_6_0-sun packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java JRE AWT setDiffICM Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(94, 119, 189, 264, 310, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-sun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-sun-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-sun-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-sun-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-sun-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-sun-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-sun-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/19");
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
if (release !~ "^(SUSE11\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.0", reference:"java-1_6_0-sun-1.6.0.u17-1.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"java-1_6_0-sun-alsa-1.6.0.u17-1.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"java-1_6_0-sun-demo-1.6.0.u17-1.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"java-1_6_0-sun-devel-1.6.0.u17-1.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"java-1_6_0-sun-jdbc-1.6.0.u17-1.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"java-1_6_0-sun-plugin-1.6.0.u17-1.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"java-1_6_0-sun-src-1.6.0.u17-1.1") ) flag++;

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
