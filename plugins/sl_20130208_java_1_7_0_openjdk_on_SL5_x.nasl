#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(64523);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/08/16 19:47:28 $");

  script_cve_id("CVE-2013-0424", "CVE-2013-0425", "CVE-2013-0426", "CVE-2013-0427", "CVE-2013-0428", "CVE-2013-0429", "CVE-2013-0431", "CVE-2013-0432", "CVE-2013-0433", "CVE-2013-0434", "CVE-2013-0435", "CVE-2013-0440", "CVE-2013-0441", "CVE-2013-0442", "CVE-2013-0443", "CVE-2013-0444", "CVE-2013-0445", "CVE-2013-0450", "CVE-2013-1475", "CVE-2013-1476", "CVE-2013-1478", "CVE-2013-1480");

  script_name(english:"Scientific Linux Security Update : java-1.7.0-openjdk on SL5.x, SL6.x i386/x86_64");
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
"Multiple improper permission check issues were discovered in the AWT,
CORBA, JMX, Libraries, and Beans components in OpenJDK. An untrusted
Java application or applet could use these flaws to bypass Java
sandbox restrictions. (CVE-2013-0442, CVE-2013-0445, CVE-2013-0441,
CVE-2013-1475, CVE-2013-1476, CVE-2013-0429, CVE-2013-0450,
CVE-2013-0425, CVE-2013-0426, CVE-2013-0428, CVE-2013-0444)

Multiple flaws were found in the way image parsers in the 2D and AWT
components handled image raster parameters. A specially crafted image
could cause Java Virtual Machine memory corruption and, possibly, lead
to arbitrary code execution with the virtual machine privileges.
(CVE-2013-1478, CVE-2013-1480)

A flaw was found in the AWT component's clipboard handling code. An
untrusted Java application or applet could use this flaw to access
clipboard data, bypassing Java sandbox restrictions. (CVE-2013-0432)

The default Java security properties configuration did not restrict
access to certain com.sun.xml.internal packages. An untrusted Java
application or applet could use this flaw to access information,
bypassing certain Java sandbox restrictions. This update lists the
whole package as restricted. (CVE-2013-0435)

Multiple improper permission check issues were discovered in the JMX,
Libraries, Networking, and JAXP components. An untrusted Java
application or applet could use these flaws to bypass certain Java
sandbox restrictions. (CVE-2013-0431, CVE-2013-0427, CVE-2013-0433,
CVE-2013-0434)

It was discovered that the RMI component's CGIHandler class used user
inputs in error messages without any sanitization. An attacker could
use this flaw to perform a cross-site scripting (XSS) attack.
(CVE-2013-0424)

It was discovered that the SSL/TLS implementation in the JSSE
component did not properly enforce handshake message ordering,
allowing an unlimited number of handshake restarts. A remote attacker
could use this flaw to make an SSL/TLS server using JSSE consume an
excessive amount of CPU by continuously restarting the handshake.
(CVE-2013-0440)

It was discovered that the JSSE component did not properly validate
Diffie- Hellman public keys. An SSL/TLS client could possibly use this
flaw to perform a small subgroup attack. (CVE-2013-0443)

This erratum also upgrades the OpenJDK package to IcedTea7 2.3.5.

All running instances of OpenJDK Java must be restarted for the update
to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1302&L=scientific-linux-errata&T=0&P=1623
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?862afd6d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet JMX Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"java-1.7.0-openjdk-1.7.0.9-2.3.5.3.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.7.0-openjdk-debuginfo-1.7.0.9-2.3.5.3.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.7.0-openjdk-demo-1.7.0.9-2.3.5.3.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.7.0-openjdk-devel-1.7.0.9-2.3.5.3.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.7.0-openjdk-javadoc-1.7.0.9-2.3.5.3.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.7.0-openjdk-src-1.7.0.9-2.3.5.3.el5_9")) flag++;

if (rpm_check(release:"SL6", reference:"java-1.7.0-openjdk-1.7.0.9-2.3.5.3.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.7.0-openjdk-debuginfo-1.7.0.9-2.3.5.3.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.7.0-openjdk-demo-1.7.0.9-2.3.5.3.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.7.0-openjdk-devel-1.7.0.9-2.3.5.3.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.7.0-openjdk-javadoc-1.7.0.9-2.3.5.3.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.7.0-openjdk-src-1.7.0.9-2.3.5.3.el6_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
