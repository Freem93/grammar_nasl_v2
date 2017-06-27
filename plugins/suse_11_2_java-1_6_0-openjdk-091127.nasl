#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update java-1_6_0-openjdk-1613.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(42926);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/21 20:21:19 $");

  script_cve_id("CVE-2009-2409", "CVE-2009-3728", "CVE-2009-3869", "CVE-2009-3871", "CVE-2009-3873", "CVE-2009-3874", "CVE-2009-3875", "CVE-2009-3876", "CVE-2009-3877", "CVE-2009-3879", "CVE-2009-3880", "CVE-2009-3881", "CVE-2009-3882", "CVE-2009-3883", "CVE-2009-3884", "CVE-2009-3885");

  script_name(english:"openSUSE Security Update : java-1_6_0-openjdk (java-1_6_0-openjdk-1613)");
  script_summary(english:"Check for the java-1_6_0-openjdk-1613 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New icedtea update to fix :

  - ICC_Profile file existence detection information leak;
    CVE-2009-3728: CVSS v2 Base Score: 5.0

  - BMP parsing DoS with UNC ICC links; CVE-2009-3885: CVSS
    v2 Base Score: 5.0

  - resurrected classloaders can still have children;
    CVE-2009-3881: CVSS v2 Base Score: 7.5

  - Numerous static security flaws in Swing; CVE-2009-3882:
    CVSS v2 Base Score: 7.5

  - Mutable statics in Windows PL&F; CVE-2009-3883: CVSS v2
    Base Score: 7.5

  - UI logging information leakage; CVE-2009-3880: CVSS v2
    Base Score: 5.0

  - GraphicsConfiguration information leak; CVE-2009-3879:
    CVSS v2 Base Score: 7.5

  - zoneinfo file existence information leak; CVE-2009-3884:
    CVSS v2 Base Score: 5.0

  - deprecate MD2 in SSL cert validation; CVE-2009-2409:
    CVSS v2 Base Score: 6.4

  - JPEG Image Writer quantization problem; CVE-2009-3873:
    CVSS v2 Base Score: 9.3

  - MessageDigest.isEqual introduces timing attack
    vulnerabilities; CVE-2009-3875: CVSS v2 Base Score: 5.0

  - OpenJDK ASN.1/DER input stream parser denial of service;
    CVE-2009-3876,CVE-2009-3877: CVSS v2 Base Score: 5.0

  - JRE AWT setDifflCM stack overflow; CVE-2009-3869: CVSS
    v2 Base Score: 9.3

  - ImageI/O JPEG heap overflow; CVE-2009-3874: CVSS v2 Base
    Score: 9.3

  - JRE AWT setBytePixels heap overflow; CVE-2009-3871: CVSS
    v2 Base Score: 9.3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=554069"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1_6_0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java JRE AWT setDiffICM Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(22, 119, 189, 200, 264, 310, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/30");
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
if (release !~ "^(SUSE11\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.2", reference:"java-1_6_0-openjdk-1.6.0.0_b16-5.10.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"java-1_6_0-openjdk-demo-1.6.0.0_b16-5.10.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"java-1_6_0-openjdk-devel-1.6.0.0_b16-5.10.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"java-1_6_0-openjdk-javadoc-1.6.0.0_b16-5.10.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"java-1_6_0-openjdk-plugin-1.6.0.0_b16-5.10.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"java-1_6_0-openjdk-src-1.6.0.0_b16-5.10.1") ) flag++;

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
