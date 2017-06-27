#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update java-1_6_0-openjdk-3500.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(53662);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/09/25 12:35:46 $");

  script_cve_id("CVE-2009-3555", "CVE-2010-3541", "CVE-2010-3548", "CVE-2010-3549", "CVE-2010-3551", "CVE-2010-3553", "CVE-2010-3554", "CVE-2010-3557", "CVE-2010-3561", "CVE-2010-3562", "CVE-2010-3564", "CVE-2010-3565", "CVE-2010-3566", "CVE-2010-3567", "CVE-2010-3568", "CVE-2010-3569", "CVE-2010-3573", "CVE-2010-3574");

  script_name(english:"openSUSE Security Update : java-1_6_0-openjdk (openSUSE-SU-2010:0957-1)");
  script_summary(english:"Check for the java-1_6_0-openjdk-3500 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Icedtea included in java-1_6_0-openjdk was updated to version
1.7.5/1.8.2/1.9.1 to fix several security issues :

  - S6914943, CVE-2009-3555: TLS: MITM attacks via session
    renegotiation

  - S6559775, CVE-2010-3568: OpenJDK Deserialization Race
    condition

  - S6891766, CVE-2010-3554: OpenJDK corba reflection
    vulnerabilities

  - S6925710, CVE-2010-3562: OpenJDK IndexColorModel
    double-free

  - S6938813, CVE-2010-3557: OpenJDK Swing mutable static

  - S6957564, CVE-2010-3548: OpenJDK DNS server IP address
    information leak

  - S6958060, CVE-2010-3564: OpenJDK kerberos vulnerability

  - S6963023, CVE-2010-3565: OpenJDK JPEG writeImage remote
    code execution

  - S6963489, CVE-2010-3566: OpenJDK ICC Profile remote code
    execution

  - S6966692, CVE-2010-3569: OpenJDK Serialization
    inconsistencies

  - S6622002, CVE-2010-3553: UIDefault.ProxyLazyValue has
    unsafe reflection usage

  - S6925672, CVE-2010-3561: Privileged ServerSocket.accept
    allows receiving connections from any host

  - S6952017, CVE-2010-3549: HttpURLConnection chunked
    encoding issue (Http request splitting)

  - S6952603, CVE-2010-3551: NetworkInterface reveals local
    network address to untrusted code

  - S6961084, CVE-2010-3541: limit setting of some request
    headers in HttpURLConnection

  - S6963285, CVE-2010-3567: Crash in ICU Opentype layout
    engine due to mismatch in character counts

  - S6980004, CVE-2010-3573: limit HTTP request cookie
    headers in HttpURLConnection

  - S6981426, CVE-2010-3574: limit use of TRACE method in
    HttpURLConnection"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2010-11/msg00024.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=642531"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1_6_0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE11.1", reference:"java-1_6_0-openjdk-1.6.0.0_b20.1.9.1-0.1.3") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"java-1_6_0-openjdk-demo-1.6.0.0_b20.1.9.1-0.1.3") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"java-1_6_0-openjdk-devel-1.6.0.0_b20.1.9.1-0.1.3") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"java-1_6_0-openjdk-javadoc-1.6.0.0_b20.1.9.1-0.1.3") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"java-1_6_0-openjdk-plugin-1.6.0.0_b20.1.9.1-0.1.3") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"java-1_6_0-openjdk-src-1.6.0.0_b20.1.9.1-0.1.3") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_6_0-openjdk / java-1_6_0-openjdk-demo / etc");
}
