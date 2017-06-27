#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-797.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(97147);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/02/15 14:34:00 $");

  script_cve_id("CVE-2016-5546", "CVE-2016-5547", "CVE-2016-5548", "CVE-2016-5552", "CVE-2017-3231", "CVE-2017-3241", "CVE-2017-3252", "CVE-2017-3253", "CVE-2017-3261", "CVE-2017-3272", "CVE-2017-3289");
  script_xref(name:"ALAS", value:"2017-797");

  script_name(english:"Amazon Linux AMI : java-1.7.0-openjdk (ALAS-2017-797)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the RMI registry and DCG implementations in the
RMI component of OpenJDK performed deserialization of untrusted
inputs. A remote attacker could possibly use this flaw to execute
arbitrary code with the privileges of RMI registry or a Java RMI
application. This issue was addressed by introducing whitelists of
classes that can be deserialized by RMI registry or DCG. These
whitelists can be customized using the newly introduced
sun.rmi.registry.registryFilter and sun.rmi.transport.dgcFilter
security properties. (CVE-2017-3241)

Multiple flaws were discovered in the Libraries and Hotspot components
in OpenJDK. An untrusted Java application or applet could use these
flaws to completely bypass Java sandbox restrictions. (CVE-2017-3272 ,
CVE-2017-3289)

A covert timing channel flaw was found in the DSA implementation in
the Libraries component of OpenJDK. A remote attacker could possibly
use this flaw to extract certain information about the used key via a
timing side channel. (CVE-2016-5548)

It was discovered that the Libraries component of OpenJDK accepted
ECSDA signatures using non-canonical DER encoding. This could cause a
Java application to accept signature in an incorrect format not
accepted by other cryptographic tools. (CVE-2016-5546)

It was discovered that the 2D component of OpenJDK performed parsing
of iTXt and zTXt PNG image chunks even when configured to ignore
metadata. An attacker able to make a Java application parse a
specially crafted PNG image could cause the application to consume an
excessive amount of memory. (CVE-2017-3253)

It was discovered that the Libraries component of OpenJDK did not
validate the length of the object identifier read from the DER input
before allocating memory to store the OID. An attacker able to make a
Java application decode a specially crafted DER input could cause the
application to consume an excessive amount of memory. (CVE-2016-5547)

It was discovered that the JAAS component of OpenJDK did not use the
correct way to extract user DN from the result of the user search LDAP
query. A specially crafted user LDAP entry could cause the application
to use an incorrect DN. (CVE-2017-3252)

It was discovered that the Networking component of OpenJDK failed to
properly parse user info from the URL. A remote attacker could cause a
Java application to incorrectly parse an attacker supplied URL and
interpret it differently from other applications processing the same
URL. (CVE-2016-5552)

Multiple flaws were found in the Networking components in OpenJDK. An
untrusted Java application or applet could use these flaws to bypass
certain Java sandbox restrictions. (CVE-2017-3261 , CVE-2017-3231)

A flaw was found in the way the DES/3DES cipher was used as part of
the TLS/SSL protocol. A man-in-the-middle attacker could use this flaw
to recover some plaintext data by capturing large amounts of encrypted
traffic between TLS/SSL server and client if the communication used a
DES/3DES based ciphersuite. This update mitigates this issue by adding
3DES cipher suites to the list of legacy algorithms (defined using the
jdk.tls.legacyAlgorithms security property) so they are only used if
connecting TLS/SSL client and server do not share any other non-legacy
cipher suite. (CVE-2016-2183)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-797.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update java-1.7.0-openjdk' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/15");
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
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-1.7.0.131-2.6.9.0.70.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-debuginfo-1.7.0.131-2.6.9.0.70.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-demo-1.7.0.131-2.6.9.0.70.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-devel-1.7.0.131-2.6.9.0.70.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-javadoc-1.7.0.131-2.6.9.0.70.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-src-1.7.0.131-2.6.9.0.70.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.7.0-openjdk / java-1.7.0-openjdk-debuginfo / etc");
}
