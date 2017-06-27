#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2012-43.
#

include("compat.inc");

if (description)
{
  script_id(69650);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/01/30 14:43:53 $");

  script_cve_id("CVE-2011-3563", "CVE-2011-3571", "CVE-2011-5035", "CVE-2012-0497", "CVE-2012-0501", "CVE-2012-0502", "CVE-2012-0503", "CVE-2012-0505", "CVE-2012-0506");
  script_xref(name:"ALAS", value:"2012-43");
  script_xref(name:"RHSA", value:"2012:0135");

  script_name(english:"Amazon Linux AMI : java-1.6.0-openjdk (ALAS-2012-43)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that Java2D did not properly check graphics
rendering objects before passing them to the native renderer.
Malicious input, or an untrusted Java application or applet could use
this flaw to crash the Java Virtual Machine (JVM), or bypass Java
sandbox restrictions. (CVE-2012-0497)

It was discovered that the exception thrown on deserialization failure
did not always contain a proper identification of the cause of the
failure. An untrusted Java application or applet could use this flaw
to bypass Java sandbox restrictions. (CVE-2012-0505)

The AtomicReferenceArray class implementation did not properly check
if the array was of the expected Object[] type. A malicious Java
application or applet could use this flaw to bypass Java sandbox
restrictions. (CVE-2011-3571)

It was discovered that the use of TimeZone.setDefault() was not
restricted by the SecurityManager, allowing an untrusted Java
application or applet to set a new default time zone, and hence bypass
Java sandbox restrictions. (CVE-2012-0503)

The HttpServer class did not limit the number of headers read from
HTTP requests. A remote attacker could use this flaw to make an
application using HttpServer use an excessive amount of CPU time via a
specially crafted request. This update introduces a header count limit
controlled using the sun.net.httpserver.maxReqHeaders property. The
default value is 200. (CVE-2011-5035)

The Java Sound component did not properly check buffer boundaries.
Malicious input, or an untrusted Java application or applet could use
this flaw to cause the Java Virtual Machine (JVM) to crash or disclose
a portion of its memory. (CVE-2011-3563)

A flaw was found in the AWT KeyboardFocusManager that could allow an
untrusted Java application or applet to acquire keyboard focus and
possibly steal sensitive information. (CVE-2012-0502)

It was discovered that the CORBA (Common Object Request Broker
Architecture) implementation in Java did not properly protect
repository identifiers on certain CORBA objects. This could have been
used to modify immutable object data. (CVE-2012-0506)

An off-by-one flaw, causing a stack overflow, was found in the
unpacker for ZIP files. A specially crafted ZIP archive could cause
the Java Virtual Machine (JVM) to crash when opened. (CVE-2012-0501)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2012-43.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update java-1.6.0-openjdk' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.6.0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.6.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.6.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.6.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.6.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"java-1.6.0-openjdk-1.6.0.0-52.1.10.6.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.6.0-openjdk-debuginfo-1.6.0.0-52.1.10.6.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.6.0-openjdk-demo-1.6.0.0-52.1.10.6.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.6.0-openjdk-devel-1.6.0.0-52.1.10.6.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-52.1.10.6.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.6.0-openjdk-src-1.6.0.0-52.1.10.6.41.amzn1")) flag++;

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
