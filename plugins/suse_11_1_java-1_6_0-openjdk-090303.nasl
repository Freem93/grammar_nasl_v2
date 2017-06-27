#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update java-1_6_0-openjdk-578.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(40238);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/21 20:09:51 $");

  script_cve_id("CVE-2008-5347", "CVE-2008-5348", "CVE-2008-5349", "CVE-2008-5350", "CVE-2008-5351", "CVE-2008-5352", "CVE-2008-5353", "CVE-2008-5354", "CVE-2008-5356", "CVE-2008-5357", "CVE-2008-5358", "CVE-2008-5359", "CVE-2008-5360");

  script_name(english:"openSUSE Security Update : java-1_6_0-openjdk (java-1_6_0-openjdk-578)");
  script_summary(english:"Check for the java-1_6_0-openjdk-578 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"OpenJDK Java 1.6.0 was upgraded to build b14, fixing quite a lot of
security issues.

It fixes at least: 4486841 UTF8 decoder should adhere to corrigendum
to Unicode 3.0.1 CVE-2008-5351 6484091 FileSystemView leaks directory
info CVE-2008-5350 aka SUN SOLVE 246266 6497740 Limit the size of RSA
public keys CVE-2008-5349 6588160 jaas krb5 client leaks OS-level UDP
sockets (all platforms) CVE-2008-5348 6592792 Add com.sun.xml.internal
to the 'package.access' property in
$JAVA_HOME/lib/security/java.security CVE-2008-5347 aka SUN SOLVE
246366 6721753 File.createTempFile produces guessable file names
CVE-2008-5360 6726779 ConvolveOp on USHORT raster can cause the JVM
crash. CVE-2008-5359 aka SUN SOLVE 244987 6733336 Crash on malformed
font CVE-2008-5356 aka SUN SOLVE 244987 6733959 Insufficient checks
for 'Main-Class' manifest entry in JAR files CVE-2008-5354 aka SUN
SOLVE 244990 6734167 Calendar.readObject allows elevation of
privileges CVE-2008-5353 6751322 Vulnerability report: Sun Java JRE
TrueType Font Parsing Heap Overflow CVE-2008-5357 aka SUN SOLVE 244987
6755943 Java JAR Pack200 Decompression should enforce stricter header
checks CVE-2008-5352 aka SUN SOLVE 244992 6766136 corrupted gif image
may cause crash in java splashscreen library. CVE-2008-5358 aka SUN
SOLVE 244987"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=471829"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1_6_0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java Calendar Deserialization Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(119, 189, 200, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/21");
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

if ( rpm_check(release:"SUSE11.1", reference:"java-1_6_0-openjdk-1.4_b14-24.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"java-1_6_0-openjdk-demo-1.4_b14-24.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"java-1_6_0-openjdk-devel-1.4_b14-24.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"java-1_6_0-openjdk-javadoc-1.4_b14-24.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"java-1_6_0-openjdk-plugin-1.4_b14-24.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"java-1_6_0-openjdk-src-1.4_b14-24.2.1") ) flag++;

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
