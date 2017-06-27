#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60776);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/11/18 01:30:19 $");

  script_cve_id("CVE-2009-3555", "CVE-2010-0082", "CVE-2010-0084", "CVE-2010-0085", "CVE-2010-0088", "CVE-2010-0091", "CVE-2010-0092", "CVE-2010-0093", "CVE-2010-0094", "CVE-2010-0095", "CVE-2010-0837", "CVE-2010-0838", "CVE-2010-0840", "CVE-2010-0845", "CVE-2010-0847", "CVE-2010-0848");

  script_name(english:"Scientific Linux Security Update : java-1.6.0-openjdk on SL5.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A flaw was found in the way the TLS/SSL (Transport Layer
Security/Secure Sockets Layer) protocols handle session renegotiation.
A man-in-the-middle attacker could use this flaw to prefix arbitrary
plain text to a client's session (for example, an HTTPS connection to
a website). This could force the server to process an attacker's
request as if authenticated using the victim's credentials.
(CVE-2009-3555)

This update disables renegotiation in the Java Secure Socket Extension
(JSSE) component. Unsafe renegotiation can be re-enabled using the
sun.security.ssl.allowUnsafeRenegotiation property.

A number of flaws have been fixed in the Java Virtual Machine (JVM)
and in various Java class implementations. These flaws could allow an
unsigned applet or application to bypass intended access restrictions.
(CVE-2010-0082, CVE-2010-0084, CVE-2010-0085, CVE-2010-0088,
CVE-2010-0094)

An untrusted applet could access clipboard information if a drag
operation was performed over that applet's canvas. This could lead to
an information leak. (CVE-2010-0091)

The rawIndex operation incorrectly handled large values, causing the
corruption of internal memory structures, resulting in an untrusted
applet or application crashing. (CVE-2010-0092)

The System.arraycopy operation incorrectly handled large index values,
potentially causing array corruption in an untrusted applet or
application. (CVE-2010-0093)

Subclasses of InetAddress may incorrectly interpret network addresses,
allowing an untrusted applet or application to bypass network access
restrictions. (CVE-2010-0095)

In certain cases, type assignments could result in 'non-exact'
interface types. This could be used to bypass type-safety
restrictions. (CVE-2010-0845)

A buffer overflow flaw in LittleCMS (embedded in OpenJDK) could cause
an untrusted applet or application using color profiles from untrusted
sources to crash. (CVE-2010-0838)

An input validation flaw was found in the JRE unpack200 functionality.
An untrusted applet or application could use this flaw to elevate its
privileges. (CVE-2010-0837)

Deferred calls to trusted applet methods could be granted incorrect
permissions, allowing an untrusted applet or application to extend its
privileges. (CVE-2010-0840)

A missing input validation flaw in the JRE could allow an attacker to
crash an untrusted applet or application. (CVE-2010-0848)

A flaw in Java2D could allow an attacker to execute arbitrary code
with the privileges of a user running an untrusted applet or
application that uses Java2D. (CVE-2010-0847)

Note: The flaws concerning applets in this advisory, CVE-2010-0082,
CVE-2010-0084, CVE-2010-0085, CVE-2010-0088, CVE-2010-0091,
CVE-2010-0092, CVE-2010-0093, CVE-2010-0094, CVE-2010-0095,
CVE-2010-0837, CVE-2010-0838, CVE-2010-0840, CVE-2010-0847, and
CVE-2010-0848, can only be triggered in java-1.6.0-openjdk by calling
the 'appletviewer' application.

This update also provides three defense in depth patches. (BZ#575745,
BZ#575861, BZ#575789)

All running instances of OpenJDK Java must be restarted for the update
to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1004&L=scientific-linux-errata&T=0&P=444
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a2d26a5c"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=575745"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=575789"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=575861"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
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
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"java-1.6.0-openjdk-1.6.0.0-1.11.b16.el5")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.6.0-openjdk-demo-1.6.0.0-1.11.b16.el5")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.6.0-openjdk-devel-1.6.0.0-1.11.b16.el5")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-1.11.b16.el5")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.6.0-openjdk-src-1.6.0.0-1.11.b16.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
