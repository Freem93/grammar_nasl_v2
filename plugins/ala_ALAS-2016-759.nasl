#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2016-759.
#

include("compat.inc");

if (description)
{
  script_id(94341);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/11/01 16:04:33 $");

  script_cve_id("CVE-2016-5542", "CVE-2016-5554", "CVE-2016-5573", "CVE-2016-5582", "CVE-2016-5597");
  script_xref(name:"ALAS", value:"2016-759");

  script_name(english:"Amazon Linux AMI : java-1.8.0-openjdk (ALAS-2016-759)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the Hotspot component of OpenJDK did not
properly check arguments of the System.arraycopy() function in certain
cases. An untrusted Java application or applet could use this flaw to
corrupt virtual machine's memory and completely bypass Java sandbox
restrictions. (CVE-2016-5582)

It was discovered that the Hotspot component of OpenJDK did not
properly check received Java Debug Wire Protocol (JDWP) packets. An
attacker could possibly use this flaw to send debugging commands to a
Java program running with debugging enabled if they could make
victim's browser send HTTP requests to the JDWP port of the debugged
application. (CVE-2016-5573)

It was discovered that the Libraries component of OpenJDK did not
restrict the set of algorithms used for JAR integrity verification.
This flaw could allow an attacker to modify content of the JAR file
that used weak signing key or hash algorithm. (CVE-2016-5542) (Note:
After this update, MD2 hash algorithm and RSA keys with less than 1024
bits are no longer allowed to be used for Jar integrity verification
by default. MD5 hash algorithm is expected to be disabled by default
in the future updates. A newly introduced security property
jdk.jar.disabledAlgorithms can be used to control the set of disabled
algorithms.)

A flaw was found in the way the JMX component of OpenJDK handled
classloaders. An untrusted Java application or applet could use this
flaw to bypass certain Java sandbox restrictions. (CVE-2016-5554)

A flaw was found in the way the Networking component of OpenJDK
handled HTTP proxy authentication. A Java application could possibly
expose HTTPS server authentication credentials via a plain text
network connection to an HTTP proxy if proxy asked for authentication.
(CVE-2016-5597)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2016-759.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update java-1.8.0-openjdk' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.8.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/28");
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
if (rpm_check(release:"ALA", reference:"java-1.8.0-openjdk-1.8.0.111-1.b15.25.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.8.0-openjdk-debuginfo-1.8.0.111-1.b15.25.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.8.0-openjdk-demo-1.8.0.111-1.b15.25.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.8.0-openjdk-devel-1.8.0.111-1.b15.25.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.8.0-openjdk-headless-1.8.0.111-1.b15.25.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.8.0-openjdk-javadoc-1.8.0.111-1.b15.25.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.8.0-openjdk-src-1.8.0.111-1.b15.25.amzn1")) flag++;

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
