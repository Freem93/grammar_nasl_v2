#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-383.
#

include("compat.inc");

if (description)
{
  script_id(78326);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/01/30 14:55:42 $");

  script_cve_id("CVE-2014-2483", "CVE-2014-2490", "CVE-2014-4209", "CVE-2014-4216", "CVE-2014-4218", "CVE-2014-4219", "CVE-2014-4221", "CVE-2014-4223", "CVE-2014-4244", "CVE-2014-4252", "CVE-2014-4262", "CVE-2014-4263", "CVE-2014-4266");
  script_xref(name:"ALAS", value:"2014-383");
  script_xref(name:"RHSA", value:"2014:0889");

  script_name(english:"Amazon Linux AMI : java-1.7.0-openjdk (ALAS-2014-383)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the Hotspot component in OpenJDK did not
properly verify bytecode from the class files. An untrusted Java
application or applet could possibly use these flaws to bypass Java
sandbox restrictions. (CVE-2014-4216 , CVE-2014-4219)

A format string flaw was discovered in the Hotspot component event
logger in OpenJDK. An untrusted Java application or applet could use
this flaw to crash the Java Virtual Machine or, potentially, execute
arbitrary code with the privileges of the Java Virtual Machine.
(CVE-2014-2490)

Multiple improper permission check issues were discovered in the
Libraries component in OpenJDK. An untrusted Java application or
applet could use these flaws to bypass Java sandbox restrictions.
(CVE-2014-4223 , CVE-2014-4262 , CVE-2014-2483)

Multiple flaws were discovered in the JMX, Libraries, Security, and
Serviceability components in OpenJDK. An untrusted Java application or
applet could use these flaws to bypass certain Java sandbox
restrictions. (CVE-2014-4209 , CVE-2014-4218 , CVE-2014-4221 ,
CVE-2014-4252 , CVE-2014-4266)

It was discovered that the RSA algorithm in the Security component in
OpenJDK did not sufficiently perform blinding while performing
operations that were using private keys. An attacker able to measure
timing differences of those operations could possibly leak information
about the used keys. (CVE-2014-4244)

The Diffie-Hellman (DH) key exchange algorithm implementation in the
Security component in OpenJDK failed to validate public DH parameters
properly. This could cause OpenJDK to accept and use weak parameters,
allowing an attacker to recover the negotiated key. (CVE-2014-4263)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-383.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update java-1.7.0-openjdk' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.7.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-1.7.0.65-2.5.1.2.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-debuginfo-1.7.0.65-2.5.1.2.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-demo-1.7.0.65-2.5.1.2.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-devel-1.7.0.65-2.5.1.2.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-javadoc-1.7.0.65-2.5.1.2.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.7.0-openjdk-src-1.7.0.65-2.5.1.2.43.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.7.0-openjdk / java-1.7.0-openjdk-debuginfo / etc");
}
