#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update java-1_5_0-sun-5133.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(31773);
  script_version ("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/22 20:32:46 $");

  script_cve_id("CVE-2008-1158", "CVE-2008-1185", "CVE-2008-1186", "CVE-2008-1187", "CVE-2008-1188", "CVE-2008-1189", "CVE-2008-1190", "CVE-2008-1191", "CVE-2008-1192", "CVE-2008-1195", "CVE-2008-1196");

  script_name(english:"openSUSE 10 Security Update : java-1_5_0-sun (java-1_5_0-sun-5133)");
  script_summary(english:"Check for the java-1_5_0-sun-5133 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Sun Java was updated to 1.5.0u15 to fix following security
vulnerabilities :

  - CVE-2008-1158: Unspecified vulnerability in the Virtual
    Machine for Sun Java Runtime Environment (JRE) and JDK 6
    Update 4 and earlier, 5.0 Update 14 and earlier, and
    SDK/JRE 1.4.2_16 and earlier allows remote attackers
    should gain privileges via an untrusted application or
    applet, a different issue than CVE-2008-1186.

  - CVE-2008-1186: Unspecified vulnerability in the Virtual
    Machine for Sun Java Runtime Environment (JRE) and JDK
    5.0 Update 13 and earlier, and SDK/JRE 1.4.2_16 and
    earlier, allows remote attackers to gain privileges via
    an untrusted application or applet, a different issue
    than CVE-2008-1185.

  - CVE-2008-1187: Unspecified vulnerability in Sun Java
    Runtime Environment (JRE) and JDK 6 Update 4 and
    earlier, 5.0 Update 14 and earlier, and SDK/JRE 1.4.2_16
    and earlier allows remote attackers to cause a denial of
    service (JRE crash) and possibly execute arbitrary code
    via unknown vectors related to XSLT transforms.

  - CVE-2008-1189: Buffer overflow in Java Web Start in Sun
    JDK and JRE 6 Update 4 and earlier, 5.0 Update 14 and
    earlier, and SDK/JRE 1.4.2_16 and earlier allows remote
    attackers to execute arbitrary code via unknown vectors,
    a different issue than CVE-2008-1188.

  - CVE-2008-1190: Unspecified vulnerability in Java Web
    Start in Sun JDK and JRE 6 Update 4 and earlier, 5.0
    Update 14 and earlier, and SDK/JRE 1.4.2_16 and earlier
    allows remote attackers to gain privileges via an
    untrusted application, a different issue than
    CVE-2008-1191.

  - CVE-2008-1192: Unspecified vulnerability in the Java
    Plug-in for Sun JDK and JRE 6 Update 4 and earlier, and
    5.0 Update 14 and earlier; and SDK and JRE 1.4.2_16 and
    earlier, and 1.3.1_21 and earlier; allows remote
    attackers to bypass the same origin policy and 'execute
    local applications' via unknown vectors.

  - CVE-2008-1195: Unspecified vulnerability in Sun JDK and
    Java Runtime Environment (JRE) 6 Update 4 and earlier
    and 5.0 Update 14 and earlier; and SDK and JRE 1.4.2_16
    and earlier; allows remote attackers to access arbitrary
    network services on the local host via unspecified
    vectors related to JavaScript and Java APIs.

  - CVE-2008-1196: Stack-based buffer overflow in Java Web
    Start (javaws.exe) in Sun JDK and JRE 6 Update 4 and
    earlier and 5.0 Update 14 and earlier; and SDK and JRE
    1.4.2_16 and earlier; allows remote attackers to execute
    arbitrary code via a crafted JNLP file."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1_5_0-sun packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(20, 119, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_5_0-sun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_5_0-sun-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_5_0-sun-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_5_0-sun-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_5_0-sun-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_5_0-sun-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_5_0-sun-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/04");
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
if (release !~ "^(SUSE10\.1|SUSE10\.2|SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1 / 10.2 / 10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"java-1_5_0-sun-1.5.0_15-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"java-1_5_0-sun-alsa-1.5.0_15-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"java-1_5_0-sun-demo-1.5.0_15-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"java-1_5_0-sun-devel-1.5.0_15-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"java-1_5_0-sun-jdbc-1.5.0_15-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"java-1_5_0-sun-plugin-1.5.0_15-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"java-1_5_0-sun-src-1.5.0_15-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"java-1_5_0-sun-1.5.0_update14-0.3") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"java-1_5_0-sun-alsa-1.5.0_update14-0.3") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"java-1_5_0-sun-demo-1.5.0_update14-0.3") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"java-1_5_0-sun-devel-1.5.0_update14-0.3") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"java-1_5_0-sun-jdbc-1.5.0_update14-0.3") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"java-1_5_0-sun-plugin-1.5.0_update14-0.3") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"java-1_5_0-sun-src-1.5.0_update14-0.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"java-1_5_0-sun-1.5.0_update15-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"java-1_5_0-sun-alsa-1.5.0_update15-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"java-1_5_0-sun-demo-1.5.0_update15-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"java-1_5_0-sun-devel-1.5.0_update15-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"java-1_5_0-sun-jdbc-1.5.0_update15-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"java-1_5_0-sun-plugin-1.5.0_update15-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"java-1_5_0-sun-src-1.5.0_update15-0.1") ) flag++;

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
