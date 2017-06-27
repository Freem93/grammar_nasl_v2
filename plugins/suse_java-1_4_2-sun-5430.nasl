#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update java-1_4_2-sun-5430.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(34035);
  script_version ("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/22 20:32:46 $");

  script_cve_id("CVE-2008-3104", "CVE-2008-3107", "CVE-2008-3108", "CVE-2008-3111", "CVE-2008-3112", "CVE-2008-3113", "CVE-2008-3114");

  script_name(english:"openSUSE 10 Security Update : java-1_4_2-sun (java-1_4_2-sun-5430)");
  script_summary(english:"Check for the java-1_4_2-sun-5430 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Sun Java was updated to 1.4.2u18 to fix following security
vulnerabilities :

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

CVE-2008-3104: Multiple unspecified vulnerabilities in Sun Java
Runtime Environment (JRE) in JDK and JRE 6 before Update 7, JDK and
JRE 5.0 before Update 16, SDK and JRE 1.4.x before 1.4.2_18, and SDK
and JRE 1.3.x before 1.3.1_23 allow remote attackers to violate the
security model for an applet's outbound connections by connecting to
localhost services running on the machine that loaded the applet."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1_4_2-sun packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(20, 119, 200, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_4_2-sun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_4_2-sun-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_4_2-sun-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_4_2-sun-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_4_2-sun-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_4_2-sun-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_4_2-sun-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686)$") audit(AUDIT_ARCH_NOT, "i586 / i686", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.2", reference:"java-1_4_2-sun-1.4.2_update18-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"java-1_4_2-sun-alsa-1.4.2_update18-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"java-1_4_2-sun-demo-1.4.2_update18-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"java-1_4_2-sun-devel-1.4.2_update18-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"java-1_4_2-sun-jdbc-1.4.2_update18-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"java-1_4_2-sun-plugin-1.4.2_update18-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"java-1_4_2-sun-src-1.4.2_update18-0.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_4_2-sun");
}
