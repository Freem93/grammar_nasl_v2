#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(70576);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/10/24 10:46:11 $");

  script_cve_id("CVE-2013-3829", "CVE-2013-4002", "CVE-2013-5772", "CVE-2013-5774", "CVE-2013-5778", "CVE-2013-5780", "CVE-2013-5782", "CVE-2013-5783", "CVE-2013-5784", "CVE-2013-5790", "CVE-2013-5797", "CVE-2013-5800", "CVE-2013-5802", "CVE-2013-5803", "CVE-2013-5804", "CVE-2013-5809", "CVE-2013-5814", "CVE-2013-5817", "CVE-2013-5820", "CVE-2013-5823", "CVE-2013-5825", "CVE-2013-5829", "CVE-2013-5830", "CVE-2013-5838", "CVE-2013-5840", "CVE-2013-5842", "CVE-2013-5849", "CVE-2013-5850", "CVE-2013-5851");

  script_name(english:"Scientific Linux Security Update : java-1.7.0-openjdk on SL6.x i386/x86_64");
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
"Multiple input checking flaws were found in the 2D component native
image parsing code. A specially crafted image file could trigger a
Java Virtual Machine memory corruption and, possibly, lead to
arbitrary code execution with the privileges of the user running the
Java Virtual Machine. (CVE-2013-5782)

The class loader did not properly check the package access for
non-public proxy classes. A remote attacker could possibly use this
flaw to execute arbitrary code with the privileges of the user running
the Java Virtual Machine. (CVE-2013-5830)

Multiple improper permission check issues were discovered in the 2D,
CORBA, JNDI, and Libraries components in OpenJDK. An untrusted Java
application or applet could use these flaws to bypass Java sandbox
restrictions. (CVE-2013-5829, CVE-2013-5814, CVE-2013-5817,
CVE-2013-5842, CVE-2013-5850, CVE-2013-5838)

Multiple input checking flaws were discovered in the JPEG image
reading and writing code in the 2D component. An untrusted Java
application or applet could use these flaws to corrupt the Java
Virtual Machine memory and bypass Java sandbox restrictions.
(CVE-2013-5809)

The FEATURE_SECURE_PROCESSING setting was not properly honored by the
javax.xml.transform package transformers. A remote attacker could use
this flaw to supply a crafted XML that would be processed without the
intended security restrictions. (CVE-2013-5802)

Multiple errors were discovered in the way the JAXP and Security
components processes XML inputs. A remote attacker could create a
crafted XML that would cause a Java application to use an excessive
amount of CPU and memory when processed. (CVE-2013-5825,
CVE-2013-4002, CVE-2013-5823)

Multiple improper permission check issues were discovered in the
Libraries, Swing, JAX-WS, JAXP, JGSS, AWT, Beans, and Scripting
components in OpenJDK. An untrusted Java application or applet could
use these flaws to bypass certain Java sandbox restrictions.
(CVE-2013-3829, CVE-2013-5840, CVE-2013-5774, CVE-2013-5783,
CVE-2013-5820, CVE-2013-5851, CVE-2013-5800, CVE-2013-5849,
CVE-2013-5790, CVE-2013-5784)

It was discovered that the 2D component image library did not properly
check bounds when performing image conversions. An untrusted Java
application or applet could use this flaw to disclose portions of the
Java Virtual Machine memory. (CVE-2013-5778)

Multiple input sanitization flaws were discovered in javadoc. When
javadoc documentation was generated from an untrusted Java source code
and hosted on a domain not controlled by the code author, these issues
could make it easier to perform cross-site scripting attacks.
(CVE-2013-5804, CVE-2013-5797)

Various OpenJDK classes that represent cryptographic keys could leak
private key information by including sensitive data in strings
returned by toString() methods. These flaws could possibly lead to an
unexpected exposure of sensitive key data. (CVE-2013-5780)

The Java Heap Analysis Tool (jhat) failed to properly escape all data
added into the HTML pages it generated. Crafted content in the memory
of a Java program analyzed using jhat could possibly be used to
conduct cross- site scripting attacks. (CVE-2013-5772)

The Kerberos implementation in OpenJDK did not properly parse KDC
responses. A malformed packet could cause a Java application using
JGSS to exit. (CVE-2013-5803)

Note: If the web browser plug-in provided by the icedtea-web package
was installed, the issues exposed via Java applets could have been
exploited without user interaction if a user visited a malicious
website.

All running instances of OpenJDK Java must be restarted for the update
to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1310&L=scientific-linux-errata&T=0&P=2228
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?955be3a2"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"java-1.7.0-openjdk-1.7.0.45-2.4.3.2.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.7.0-openjdk-debuginfo-1.7.0.45-2.4.3.2.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.7.0-openjdk-demo-1.7.0.45-2.4.3.2.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.7.0-openjdk-devel-1.7.0.45-2.4.3.2.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.7.0-openjdk-javadoc-1.7.0.45-2.4.3.2.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.7.0-openjdk-src-1.7.0.45-2.4.3.2.el6_4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
