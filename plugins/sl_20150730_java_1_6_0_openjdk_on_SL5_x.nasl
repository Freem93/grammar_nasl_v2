#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(85212);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/14 20:33:26 $");

  script_cve_id("CVE-2015-2590", "CVE-2015-2601", "CVE-2015-2621", "CVE-2015-2625", "CVE-2015-2628", "CVE-2015-2632", "CVE-2015-2808", "CVE-2015-4000", "CVE-2015-4731", "CVE-2015-4732", "CVE-2015-4733", "CVE-2015-4748", "CVE-2015-4749", "CVE-2015-4760");

  script_name(english:"Scientific Linux Security Update : java-1.6.0-openjdk on SL5.x, SL6.x, SL7.x i386/x86_64 (Bar Mitzvah) (Logjam)");
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
"Multiple flaws were discovered in the 2D, CORBA, JMX, Libraries and
RMI components in OpenJDK. An untrusted Java application or applet
could use these flaws to bypass Java sandbox restrictions.
(CVE-2015-4760, CVE-2015-2628, CVE-2015-4731, CVE-2015-2590,
CVE-2015-4732, CVE-2015-4733)

A flaw was found in the way the Libraries component of OpenJDK
verified Online Certificate Status Protocol (OCSP) responses. An OCSP
response with no nextUpdate date specified was incorrectly handled as
having unlimited validity, possibly causing a revoked X.509
certificate to be interpreted as valid. (CVE-2015-4748)

It was discovered that the JCE component in OpenJDK failed to use
constant time comparisons in multiple cases. An attacker could
possibly use these flaws to disclose sensitive information by
measuring the time used to perform operations using these non-constant
time comparisons. (CVE-2015-2601)

A flaw was found in the RC4 encryption algorithm. When using certain
keys for RC4 encryption, an attacker could obtain portions of the
plain text from the cipher text without the knowledge of the
encryption key. (CVE-2015-2808)

A flaw was found in the way the TLS protocol composed the
Diffie-Hellman (DH) key exchange. A man-in-the-middle attacker could
use this flaw to force the use of weak 512 bit export-grade keys
during the key exchange, allowing them to decrypt all traffic.
(CVE-2015-4000)

It was discovered that the JNDI component in OpenJDK did not handle
DNS resolutions correctly. An attacker able to trigger such DNS errors
could cause a Java application using JNDI to consume memory and CPU
time, and possibly block further DNS resolution. (CVE-2015-4749)

Multiple information leak flaws were found in the JMX and 2D
components in OpenJDK. An untrusted Java application or applet could
use this flaw to bypass certain Java sandbox restrictions.
(CVE-2015-2621, CVE-2015-2632)

A flaw was found in the way the JSSE component in OpenJDK performed
X.509 certificate identity verification when establishing a TLS/SSL
connection to a host identified by an IP address. In certain cases,
the certificate was accepted as valid if it was issued for a host name
to which the IP address resolves rather than for the IP address.
(CVE-2015-2625)

All running instances of OpenJDK Java must be restarted for the update
to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1508&L=scientific-linux-errata&F=&S=&P=8436
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fcae96fb"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/30");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"java-1.6.0-openjdk-1.6.0.36-1.13.8.1.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.6.0-openjdk-debuginfo-1.6.0.36-1.13.8.1.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.6.0-openjdk-demo-1.6.0.36-1.13.8.1.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.6.0-openjdk-devel-1.6.0.36-1.13.8.1.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.6.0-openjdk-javadoc-1.6.0.36-1.13.8.1.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.6.0-openjdk-src-1.6.0.36-1.13.8.1.el5_11")) flag++;

if (rpm_check(release:"SL6", reference:"java-1.6.0-openjdk-1.6.0.36-1.13.8.1.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.6.0-openjdk-debuginfo-1.6.0.36-1.13.8.1.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.6.0-openjdk-demo-1.6.0.36-1.13.8.1.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.6.0-openjdk-devel-1.6.0.36-1.13.8.1.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.6.0-openjdk-javadoc-1.6.0.36-1.13.8.1.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.6.0-openjdk-src-1.6.0.36-1.13.8.1.el6_7")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.6.0-openjdk-1.6.0.36-1.13.8.1.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.6.0-openjdk-debuginfo-1.6.0.36-1.13.8.1.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.6.0-openjdk-demo-1.6.0.36-1.13.8.1.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.6.0-openjdk-devel-1.6.0.36-1.13.8.1.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.6.0-openjdk-javadoc-1.6.0.36-1.13.8.1.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.6.0-openjdk-src-1.6.0.36-1.13.8.1.el7_1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
