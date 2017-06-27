#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-571.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(84931);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/11/11 19:58:28 $");

  script_cve_id("CVE-2015-0383", "CVE-2015-2590", "CVE-2015-2601", "CVE-2015-2621", "CVE-2015-2625", "CVE-2015-2628", "CVE-2015-2632", "CVE-2015-2659", "CVE-2015-2808", "CVE-2015-3149", "CVE-2015-4000", "CVE-2015-4731", "CVE-2015-4732", "CVE-2015-4733", "CVE-2015-4748", "CVE-2015-4749", "CVE-2015-4760");
  script_xref(name:"ALAS", value:"2015-571");
  script_xref(name:"RHSA", value:"2015:1228");

  script_name(english:"Amazon Linux AMI : java-1.8.0-openjdk (ALAS-2015-571) (Bar Mitzvah) (Logjam)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple flaws were discovered in the 2D, CORBA, JMX, Libraries and
RMI components in OpenJDK. An untrusted Java application or applet
could use these flaws to bypass Java sandbox restrictions.
(CVE-2015-4760 , CVE-2015-2628 , CVE-2015-4731 , CVE-2015-2590 ,
CVE-2015-4732 , CVE-2015-4733)

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

It was discovered that the GCM (Galois Counter Mode) implementation in
the Security component of OpenJDK failed to properly perform a null
check. This could cause the Java Virtual Machine to crash when an
application performed encryption using a block cipher in the GCM mode.
(CVE-2015-2659)

A flaw was found in the RC4 encryption algorithm. When using certain
keys for RC4 encryption, an attacker could obtain portions of the
plain text from the cipher text without the knowledge of the
encryption key. (CVE-2015-2808)

Please note that with this update, OpenJDK now disables RC4 TLS/SSL
cipher suites by default to address the CVE-2015-2808 issue.

A flaw was found in the way the TLS protocol composed the
Diffie-Hellman (DH) key exchange. A man-in-the-middle attacker could
use this flaw to force the use of weak 512 bit export-grade keys
during the key exchange, allowing them do decrypt all traffic.
(CVE-2015-4000)

Please note that this update forces the TLS/SSL client implementation
in OpenJDK to reject DH key sizes below 768 bits, which prevents
sessions to be downgraded to export-grade keys.

It was discovered that the JNDI component in OpenJDK did not handle
DNS resolutions correctly. An attacker able to trigger such DNS errors
could cause a Java application using JNDI to consume memory and CPU
time, and possibly block further DNS resolution. (CVE-2015-4749)

Multiple information leak flaws were found in the JMX and 2D
components in OpenJDK. An untrusted Java application or applet could
use this flaw to bypass certain Java sandbox restrictions.
(CVE-2015-2621 , CVE-2015-2632)

A flaw was found in the way the JSSE component in OpenJDK performed
X.509 certificate identity verification when establishing a TLS/SSL
connection to a host identified by an IP address. In certain cases,
the certificate was accepted as valid if it was issued for a host name
to which the IP address resolves rather than for the IP address.
(CVE-2015-2625)

Multiple insecure temporary file use issues were found in the way the
Hotspot component in OpenJDK created performance statistics and error
log files. A local attacker could possibly make a victim using OpenJDK
overwrite arbitrary files using a symlink attack."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-571.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update java-1.8.0-openjdk' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/22");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/AmazonLinux/release")) audit(AUDIT_OS_NOT, "Amazon Linux AMI");
if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"java-1.8.0-openjdk-1.8.0.51-1.b16.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.8.0-openjdk-debuginfo-1.8.0.51-1.b16.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.8.0-openjdk-demo-1.8.0.51-1.b16.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.8.0-openjdk-devel-1.8.0.51-1.b16.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.8.0-openjdk-headless-1.8.0.51-1.b16.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.8.0-openjdk-javadoc-1.8.0.51-1.b16.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.8.0-openjdk-src-1.8.0.51-1.b16.6.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.8.0-openjdk / java-1.8.0-openjdk-debuginfo / etc");
}
