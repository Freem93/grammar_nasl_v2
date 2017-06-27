#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update java-1_6_0-openjdk-2362.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(46189);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2014/06/13 19:49:34 $");

  script_cve_id("CVE-2009-3555", "CVE-2010-0082", "CVE-2010-0084", "CVE-2010-0085", "CVE-2010-0088", "CVE-2010-0091", "CVE-2010-0092", "CVE-2010-0093", "CVE-2010-0094", "CVE-2010-0095", "CVE-2010-0837", "CVE-2010-0838", "CVE-2010-0840", "CVE-2010-0845", "CVE-2010-0847", "CVE-2010-0848");

  script_name(english:"openSUSE Security Update : java-1_6_0-openjdk (openSUSE-SU-2010:0182-1)");
  script_summary(english:"Check for the java-1_6_0-openjdk-2362 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"java-1_6_0-openjdk version 1.7.3 fixes serveral security issues :

  - CVE-2010-0837: JAR 'unpack200' must verify input
    parameters

  - CVE-2010-0845: No ClassCastException for
    HashAttributeSet constructors if run with -Xcomp

  - CVE-2010-0838: CMM readMabCurveData Buffer Overflow
    Vulnerability

  - CVE-2010-0082: Loader-constraint table allows arrays
    instead of only the base-classes

  - CVE-2010-0095: Subclasses of InetAddress may incorrectly
    interpret network addresses

  - CVE-2010-0085: File TOCTOU deserialization vulnerability

  - CVE-2010-0091: Unsigned applet can retrieve the dragged
    information before drop action occurs

  - CVE-2010-0088: Inflater/Deflater clone issues

  - CVE-2010-0084: Policy/PolicyFile leak dynamic
    ProtectionDomains.

  - CVE-2010-0092: AtomicReferenceArray causes SIGSEGV ->
    SEGV_MAPERR error

  - CVE-2010-0094: Deserialization of RMIConnectionImpl
    objects should enforce stricter checks

  - CVE-2010-0093: System.arraycopy unable to reference
    elements beyond Integer.MAX_VALUE bytes

  - CVE-2010-0840: Applet Trusted Methods Chaining Privilege
    Escalation Vulnerability

  - CVE-2010-0848: AWT Library Invalid Index Vulnerability

  - CVE-2010-0847: ImagingLib arbitrary code execution
    vulnerability

  - CVE-2009-3555: TLS: MITM attacks via session
    renegotiation"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2010-04/msg00090.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=594415"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1_6_0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Statement.invoke() Trusted Method Chain Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE11.1", reference:"java-1_6_0-openjdk-1.6.0.0_b17-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"java-1_6_0-openjdk-demo-1.6.0.0_b17-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"java-1_6_0-openjdk-devel-1.6.0.0_b17-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"java-1_6_0-openjdk-javadoc-1.6.0.0_b17-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"java-1_6_0-openjdk-plugin-1.6.0.0_b17-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"java-1_6_0-openjdk-src-1.6.0.0_b17-2.3.1") ) flag++;

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
