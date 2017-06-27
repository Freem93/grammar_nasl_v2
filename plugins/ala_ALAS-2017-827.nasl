#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-827.
#

include("compat.inc");

if (description)
{
  script_id(100105);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/11 13:20:58 $");

  script_cve_id("CVE-2016-5542", "CVE-2017-3509", "CVE-2017-3511", "CVE-2017-3526", "CVE-2017-3533", "CVE-2017-3539", "CVE-2017-3544");
  script_xref(name:"ALAS", value:"2017-827");

  script_name(english:"Amazon Linux AMI : java-1.8.0-openjdk (ALAS-2017-827)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Improper re-use of NTLM authenticated connections (Networking,
8163520) :

It was discovered that the HTTP client implementation in the
Networking component of OpenJDK could cache and re-use an NTLM
authenticated connection in a different security context. A remote
attacker could possibly use this flaw to make a Java application
perform HTTP requests authenticated with credentials of a different
user. (CVE-2017-3509)

Newline injection in the SMTP client (Networking, 8171533) :

A newline injection flaw was discovered in the SMTP client
implementation in the Networking component in OpenJDK. A remote
attacker could possibly use this flaw to manipulate SMTP connections
established by a Java application. (CVE-2017-3544)

Newline injection in the FTP client (Networking, 8170222)

A newline injection flaw was discovered in the FTP client
implementation in the Networking component in OpenJDK. A remote
attacker could possibly use this flaw to manipulate FTP connections
established by a Java application. (CVE-2017-3533)

Missing algorithm restrictions for jar verification (Libraries,
8155973) :

It was discovered that the Libraries component of OpenJDK did not
restrict the set of algorithms used for JAR integrity verification.
This flaw could allow an attacker to modify content of the JAR file
that used weak signing key or hash algorithm. (CVE-2016-5542)

Untrusted extension directories search path in Launcher (JCE, 8163528)

An untrusted library search path flaw was found in the JCE component
of OpenJDK. A local attacker could possibly use this flaw to cause a
Java application using JCE to load an attacker-controlled library and
hence escalate their privileges. (CVE-2017-3511)

MD5 allowed for jar verification (Security, 8171121)

It was discovered that the Security component of OpenJDK did not allow
users to restrict the set of algorithms allowed for Jar integrity
verification. This flaw could allow an attacker to modify content of
the Jar file that used weak signing key or hash algorithm.
(CVE-2017-3539)

Incomplete XML parse tree size enforcement (JAXP, 8169011)

It was found that the JAXP component of OpenJDK failed to correctly
enforce parse tree size limits when parsing XML document. An attacker
able to make a Java application parse a specially crafted XML document
could use this flaw to make it consume an excessive amount of CPU and
memory. (CVE-2017-3526)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-827.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update java-1.8.0-openjdk' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-javadoc-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"java-1.8.0-openjdk-1.8.0.131-2.b11.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.8.0-openjdk-debuginfo-1.8.0.131-2.b11.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.8.0-openjdk-demo-1.8.0.131-2.b11.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.8.0-openjdk-devel-1.8.0.131-2.b11.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.8.0-openjdk-headless-1.8.0.131-2.b11.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.8.0-openjdk-javadoc-1.8.0.131-2.b11.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.8.0-openjdk-javadoc-zip-1.8.0.131-2.b11.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.8.0-openjdk-src-1.8.0.131-2.b11.30.amzn1")) flag++;

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
