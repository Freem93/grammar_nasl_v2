#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update java-1_5_0-sun-96.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(39996);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/21 20:09:49 $");

  script_cve_id("CVE-2008-3103", "CVE-2008-3104", "CVE-2008-3105", "CVE-2008-3106", "CVE-2008-3107", "CVE-2008-3108", "CVE-2008-3111", "CVE-2008-3112", "CVE-2008-3113", "CVE-2008-3114", "CVE-2008-3115");

  script_name(english:"openSUSE Security Update : java-1_5_0-sun (java-1_5_0-sun-96)");
  script_summary(english:"Check for the java-1_5_0-sun-96 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Sun Java was updated to 1.5.0u16 to fix following security
vulnerabilities :

CVE-2008-3115: Secure Static Versioning in Sun Java JDK and JRE 6
Update 6 and earlier, and 5.0 Update 6 through 15, does not properly
prevent execution of applets on older JRE releases, which might allow
remote attackers to exploit vulnerabilities in these older releases.

CVE-2008-3114: Unspecified vulnerability in Sun Java Web Start in JDK
and JRE 6 before Update 7, JDK and JRE 5.0 before Update 16, and SDK
and JRE 1.4.x before 1.4.2_18 allows context-dependent attackers to
obtain sensitive information (the cache location) via an untrusted
application, aka CR 6704074. 

CVE-2008-3113: Unspecified vulnerability in Sun Java Web Start in JDK
and JRE 5.0 before Update 16 and SDK and JRE 1.4.x before 1.4.2_18
allows remote attackers to create or delete arbitrary files via an
untrusted application, aka CR 6704077. 

CVE-2008-3112: Unspecified vulnerability in Sun Java Web Start in JDK
and JRE 6 before Update 7, JDK and JRE 5.0 before Update 16, and SDK
and JRE 1.4.x before 1.4.2_18 allows remote attackers to create
arbitrary files via an untrusted application, aka CR 6703909. 

CVE-2008-3111: Multiple buffer overflows in Sun Java Web Start in JDK
and JRE 6 before Update 4, JDK and JRE 5.0 before Update 16, and SDK
and JRE 1.4.x before 1.4.2_18 allow context-dependent attackers to
gain privileges via an untrusted application, as demonstrated by an
application that grants itself privileges to (1) read local files, (2)
write to local files, or (3) execute local programs, aka CR 6557220.

CVE-2008-3108: Buffer overflow in Sun Java Runtime Environment (JRE)
in JDK and JRE 5.0 before Update 10, SDK and JRE 1.4.x before
1.4.2_18, and SDK and JRE 1.3.x before 1.3.1_23 allows
context-dependent attackers to gain privileges via unspecified vectors
related to font processing. 

CVE-2008-3107: Unspecified vulnerability in the Virtual Machine in Sun
Java Runtime Environment (JRE) in JDK and JRE 6 before Update 7, JDK
and JRE 5.0 before Update 16, and SDK and JRE 1.4.x before 1.4.2_18
allows context-dependent attackers to gain privileges via an untrusted
(1) application or (2) applet, as demonstrated by an application or
applet that grants itself privileges to (a) read local files, (b)
write to local files, or (c) execute local programs.

CVE-2008-3106: Unspecified vulnerability in Sun Java Runtime
Environment (JRE) in JDK and JRE 6 Update 6 and earlier and JDK and
JRE 5.0 Update 15 and earlier allows remote attackers to access URLs
via unknown vectors involving processing of XML data by an untrusted
(1) application or (2) applet, a different vulnerability than
CVE-2008-3105. 

CVE-2008-3104: Multiple unspecified vulnerabilities in Sun Java
Runtime Environment (JRE) in JDK and JRE 6 before Update 7, JDK and
JRE 5.0 before Update 16, SDK and JRE 1.4.x before 1.4.2_18, and SDK
and JRE 1.3.x before 1.3.1_23 allow remote attackers to violate the
security model for an applet's outbound connections by connecting to
localhost services running on the machine that loaded the applet. 

CVE-2008-3103: Unspecified vulnerability in the Java Management
Extensions (JMX) management agent in Sun Java Runtime Environment
(JRE) in JDK and JRE 6 Update 6 and earlier and JDK and JRE 5.0 Update
15 and earlier, when local monitoring is enabled, allows remote
attackers to 'perform unauthorized operations' via unspecified
vectors."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=407935"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1_5_0-sun packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(16, 20, 119, 200, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_5_0-sun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_5_0-sun-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_5_0-sun-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_5_0-sun-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_5_0-sun-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_5_0-sun-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_5_0-sun-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/15");
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
if (release !~ "^(SUSE11\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.0", reference:"java-1_5_0-sun-1.5.0_update16-1.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"java-1_5_0-sun-alsa-1.5.0_update16-1.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"java-1_5_0-sun-demo-1.5.0_update16-1.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"java-1_5_0-sun-devel-1.5.0_update16-1.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"java-1_5_0-sun-jdbc-1.5.0_update16-1.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"java-1_5_0-sun-plugin-1.5.0_update16-1.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"java-1_5_0-sun-src-1.5.0_update16-1.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_5_0-sun");
}
