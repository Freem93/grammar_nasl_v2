#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2016-700.
#

include("compat.inc");

if (description)
{
  script_id(91048);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/07 15:17:41 $");

  script_cve_id("CVE-2016-0686", "CVE-2016-0687", "CVE-2016-0695", "CVE-2016-3425", "CVE-2016-3427");
  script_xref(name:"ALAS", value:"2016-700");

  script_name(english:"Amazon Linux AMI : java-1.6.0-openjdk (ALAS-2016-700)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple flaws were discovered in the Serialization and Hotspot
components in OpenJDK. An untrusted Java application or applet could
use these flaws to completely bypass Java sandbox restrictions.
(CVE-2016-0686 , CVE-2016-0687)

It was discovered that the RMI server implementation in the JMX
component in OpenJDK did not restrict which classes can be
deserialized when deserializing authentication credentials. A remote,
unauthenticated attacker able to connect to a JMX port could possibly
use this flaw to trigger deserialization flaws. (CVE-2016-3427)

It was discovered that the JAXP component in OpenJDK failed to
properly handle Unicode surrogate pairs used as part of the XML
attribute values. Specially crafted XML input could cause a Java
application to use an excessive amount of memory when parsed.
(CVE-2016-3425)

It was discovered that the Security component in OpenJDK failed to
check the digest algorithm strength when generating DSA signatures.
The use of a digest weaker than the key strength could lead to the
generation of signatures that were weaker than expected.
(CVE-2016-0695)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2016-700.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update java-1.6.0-openjdk' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.6.0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.6.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.6.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.6.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.6.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"java-1.6.0-openjdk-1.6.0.39-1.13.11.1.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.6.0-openjdk-debuginfo-1.6.0.39-1.13.11.1.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.6.0-openjdk-demo-1.6.0.39-1.13.11.1.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.6.0-openjdk-devel-1.6.0.39-1.13.11.1.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.6.0-openjdk-javadoc-1.6.0.39-1.13.11.1.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.6.0-openjdk-src-1.6.0.39-1.13.11.1.74.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.6.0-openjdk / java-1.6.0-openjdk-debuginfo / etc");
}
