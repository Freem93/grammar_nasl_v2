#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-511.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(85001);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/12/07 20:46:54 $");

  script_cve_id("CVE-2015-2590", "CVE-2015-2596", "CVE-2015-2597", "CVE-2015-2601", "CVE-2015-2613", "CVE-2015-2619", "CVE-2015-2621", "CVE-2015-2625", "CVE-2015-2627", "CVE-2015-2628", "CVE-2015-2632", "CVE-2015-2637", "CVE-2015-2638", "CVE-2015-2664", "CVE-2015-2808", "CVE-2015-4000", "CVE-2015-4729", "CVE-2015-4731", "CVE-2015-4732", "CVE-2015-4733", "CVE-2015-4736", "CVE-2015-4748", "CVE-2015-4749", "CVE-2015-4760");

  script_name(english:"openSUSE Security Update : java-1_7_0-openjdk (openSUSE-2015-511) (Bar Mitzvah) (Logjam)");
  script_summary(english:"Check for the openSUSE-2015-511 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"OpenJDK was updated to 2.6.1 - OpenJDK 7u85 to fix security issues and
bugs.

The following vulnerabilities were fixed :

  - CVE-2015-2590: Easily exploitable vulnerability in the
    Libraries component allowed successful unauthenticated
    network attacks via multiple protocols. Successful
    attack of this vulnerability could have resulted in
    unauthorized Operating System takeover including
    arbitrary code execution.

  - CVE-2015-2596: Difficult to exploit vulnerability in the
    Hotspot component allowed successful unauthenticated
    network attacks via multiple protocols. Successful
    attack of this vulnerability could have resulted in
    unauthorized update, insert or delete access to some
    Java accessible data.

  - CVE-2015-2597: Easily exploitable vulnerability in the
    Install component requiring logon to Operating System.
    Successful attack of this vulnerability could have
    resulted in unauthorized Operating System takeover
    including arbitrary code execution.

  - CVE-2015-2601: Easily exploitable vulnerability in the
    JCE component allowed successful unauthenticated network
    attacks via multiple protocols. Successful attack of
    this vulnerability could have resulted in unauthorized
    read access to a subset of Java accessible data.

  - CVE-2015-2613: Easily exploitable vulnerability in the
    JCE component allowed successful unauthenticated network
    attacks via multiple protocols. Successful attack of
    this vulnerability could have resulted in unauthorized
    read access to a subset of Java SE, Java SE Embedded
    accessible data.

  - CVE-2015-2619: Easily exploitable vulnerability in the
    2D component allowed successful unauthenticated network
    attacks via multiple protocols. Successful attack of
    this vulnerability could have resulted in unauthorized
    read access to a subset of Java accessible data.

  - CVE-2015-2621: Easily exploitable vulnerability in the
    JMX component allowed successful unauthenticated network
    attacks via multiple protocols. Successful attack of
    this vulnerability could have resulted in unauthorized
    read access to a subset of Java accessible data.

  - CVE-2015-2625: Very difficult to exploit vulnerability
    in the JSSE component allowed successful unauthenticated
    network attacks via SSL/TLS. Successful attack of this
    vulnerability could have resulted in unauthorized read
    access to a subset of Java accessible data.

  - CVE-2015-2627: Very difficult to exploit vulnerability
    in the Install component allowed successful
    unauthenticated network attacks via multiple protocols.
    Successful attack of this vulnerability could have
    resulted in unauthorized read access to a subset of Java
    accessible data.

  - CVE-2015-2628: Easily exploitable vulnerability in the
    CORBA component allowed successful unauthenticated
    network attacks via multiple protocols. Successful
    attack of this vulnerability could have resulted in
    unauthorized Operating System takeover including
    arbitrary code execution.

  - CVE-2015-2632: Easily exploitable vulnerability in the
    2D component allowed successful unauthenticated network
    attacks via multiple protocols. Successful attack of
    this vulnerability could have resulted in unauthorized
    read access to a subset of Java accessible data.

  - CVE-2015-2637: Easily exploitable vulnerability in the
    2D component allowed successful unauthenticated network
    attacks via multiple protocols. Successful attack of
    this vulnerability could have resulted in unauthorized
    read access to a subset of Java accessible data.

  - CVE-2015-2638: Easily exploitable vulnerability in the
    2D component allowed successful unauthenticated network
    attacks via multiple protocols. Successful attack of
    this vulnerability could have resulted in unauthorized
    Operating System takeover including arbitrary code
    execution.

  - CVE-2015-2664: Difficult to exploit vulnerability in the
    Deployment component requiring logon to Operating
    System. Successful attack of this vulnerability could
    have resulted in unauthorized Operating System takeover
    including arbitrary code execution.

  - CVE-2015-2808: Very difficult to exploit vulnerability
    in the JSSE component allowed successful unauthenticated
    network attacks via SSL/TLS. Successful attack of this
    vulnerability could have resulted in unauthorized
    update, insert or delete access to some Java accessible
    data as well as read access to a subset of Java
    accessible data.

  - CVE-2015-4000: Very difficult to exploit vulnerability
    in the JSSE component allowed successful unauthenticated
    network attacks via SSL/TLS. Successful attack of this
    vulnerability could have resulted in unauthorized
    update, insert or delete access to some Java accessible
    data as well as read access to a subset of Java Embedded
    accessible data. 

  - CVE-2015-4729: Very difficult to exploit vulnerability
    in the Deployment component allowed successful
    unauthenticated network attacks via multiple protocols.
    Successful attack of this vulnerability could have
    resulted in unauthorized update, insert or delete access
    to some Java SE accessible data as well as read access
    to a subset of Java SE accessible data.

  - CVE-2015-4731: Easily exploitable vulnerability in the
    JMX component allowed successful unauthenticated network
    attacks via multiple protocols. Successful attack of
    this vulnerability could have resulted in unauthorized
    Operating System takeover including arbitrary code
    execution.

  - CVE-2015-4732: Easily exploitable vulnerability in the
    Libraries component allowed successful unauthenticated
    network attacks via multiple protocols. Successful
    attack of this vulnerability could have resulted in
    unauthorized Operating System takeover including
    arbitrary code execution.

  - CVE-2015-4733: Easily exploitable vulnerability in the
    RMI component allowed successful unauthenticated network
    attacks via multiple protocols. Successful attack of
    this vulnerability could have resulted in unauthorized
    Operating System takeover including arbitrary code
    execution.

  - CVE-2015-4736: Difficult to exploit vulnerability in the
    Deployment component allowed successful unauthenticated
    network attacks via multiple protocols. Successful
    attack of this vulnerability could have resulted in
    unauthorized Operating System takeover including
    arbitrary code execution.

  - CVE-2015-4748: Very difficult to exploit vulnerability
    in the Security component allowed successful
    unauthenticated network attacks via OCSP. Successful
    attack of this vulnerability could have resulted in
    unauthorized Operating System takeover including
    arbitrary code execution.

  - CVE-2015-4749: Difficult to exploit vulnerability in the
    JNDI component allowed successful unauthenticated
    network attacks via multiple protocols. Successful
    attack of this vulnerability could have resulted in
    unauthorized ability to cause a partial denial of
    service (partial DOS).

  - CVE-2015-4760: Easily exploitable vulnerability in the
    2D component allowed successful unauthenticated network
    attacks via multiple protocols. Successful attack of
    this vulnerability could have resulted in unauthorized
    Operating System takeover including arbitrary code
    execution."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=937828"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=938248"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1_7_0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-bootstrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-bootstrap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-bootstrap-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-bootstrap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-bootstrap-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-bootstrap-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-bootstrap-headless-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/22");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-1.7.0.85-24.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-accessibility-1.7.0.85-24.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-debuginfo-1.7.0.85-24.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-debugsource-1.7.0.85-24.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-demo-1.7.0.85-24.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-demo-debuginfo-1.7.0.85-24.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-devel-1.7.0.85-24.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-devel-debuginfo-1.7.0.85-24.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-headless-1.7.0.85-24.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-headless-debuginfo-1.7.0.85-24.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-javadoc-1.7.0.85-24.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-src-1.7.0.85-24.21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-1.7.0.85-10.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-accessibility-1.7.0.85-10.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-bootstrap-1.7.0.85-10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-bootstrap-debuginfo-1.7.0.85-10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-bootstrap-debugsource-1.7.0.85-10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-bootstrap-devel-1.7.0.85-10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-bootstrap-devel-debuginfo-1.7.0.85-10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-bootstrap-headless-1.7.0.85-10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-bootstrap-headless-debuginfo-1.7.0.85-10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-debuginfo-1.7.0.85-10.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-debugsource-1.7.0.85-10.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-demo-1.7.0.85-10.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-demo-debuginfo-1.7.0.85-10.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-devel-1.7.0.85-10.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-devel-debuginfo-1.7.0.85-10.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-headless-1.7.0.85-10.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-headless-debuginfo-1.7.0.85-10.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-javadoc-1.7.0.85-10.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"java-1_7_0-openjdk-src-1.7.0.85-10.2") ) flag++;

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
