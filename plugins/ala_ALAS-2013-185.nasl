#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2013-185.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(69744);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/01/30 14:43:53 $");

  script_cve_id("CVE-2013-0401", "CVE-2013-1488", "CVE-2013-1518", "CVE-2013-1537", "CVE-2013-1557", "CVE-2013-1558", "CVE-2013-1569", "CVE-2013-2383", "CVE-2013-2384", "CVE-2013-2415", "CVE-2013-2417", "CVE-2013-2419", "CVE-2013-2420", "CVE-2013-2421", "CVE-2013-2422", "CVE-2013-2424", "CVE-2013-2426", "CVE-2013-2429", "CVE-2013-2430", "CVE-2013-2431");
  script_xref(name:"ALAS", value:"2013-185");
  script_xref(name:"RHSA", value:"2013:0770");

  script_name(english:"Amazon Linux AMI : java-1.6.0-openjdk (ALAS-2013-185)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple flaws were discovered in the font layout engine in the 2D
component. An untrusted Java application or applet could possibly use
these flaws to trigger Java Virtual Machine memory corruption.
(CVE-2013-1569 , CVE-2013-2383 , CVE-2013-2384)

Multiple improper permission check issues were discovered in the
Beans, Libraries, JAXP, and RMI components in OpenJDK. An untrusted
Java application or applet could use these flaws to bypass Java
sandbox restrictions. (CVE-2013-1558 , CVE-2013-2422 , CVE-2013-1518 ,
CVE-2013-1557)

The previous default value of the java.rmi.server.useCodebaseOnly
property permitted the RMI implementation to automatically load
classes from remotely specified locations. An attacker able to connect
to an application using RMI could use this flaw to make the
application execute arbitrary code. (CVE-2013-1537)

The 2D component did not properly process certain images. An untrusted
Java application or applet could possibly use this flaw to trigger
Java Virtual Machine memory corruption. (CVE-2013-2420)

It was discovered that the Hotspot component did not properly handle
certain intrinsic frames, and did not correctly perform MethodHandle
lookups. An untrusted Java application or applet could use these flaws
to bypass Java sandbox restrictions. (CVE-2013-2431 , CVE-2013-2421)

It was discovered that JPEGImageReader and JPEGImageWriter in the
ImageIO component did not protect against modification of their state
while performing certain native code operations. An untrusted Java
application or applet could possibly use these flaws to trigger Java
Virtual Machine memory corruption. (CVE-2013-2429 , CVE-2013-2430)

The JDBC driver manager could incorrectly call the toString() method
in JDBC drivers, and the ConcurrentHashMap class could incorrectly
call the defaultReadObject() method. An untrusted Java application or
applet could possibly use these flaws to bypass Java sandbox
restrictions. (CVE-2013-1488 , CVE-2013-2426)

The sun.awt.datatransfer.ClassLoaderObjectInputStream class may
incorrectly invoke the system class loader. An untrusted Java
application or applet could possibly use this flaw to bypass certain
Java sandbox restrictions. (CVE-2013-0401)

Flaws were discovered in the Network component's InetAddress
serialization, and the 2D component's font handling. An untrusted Java
application or applet could possibly use these flaws to crash the Java
Virtual Machine. (CVE-2013-2417 , CVE-2013-2419)

The MBeanInstantiator class implementation in the OpenJDK JMX
component did not properly check class access before creating new
instances. An untrusted Java application or applet could use this flaw
to create instances of non-public classes. (CVE-2013-2424)

It was discovered that JAX-WS could possibly create temporary files
with insecure permissions. A local attacker could use this flaw to
access temporary files created by an application using JAX-WS.
(CVE-2013-2415)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2013-185.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update java-1.6.0-openjdk' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Driver Manager Privileged toString() Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.6.0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.6.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.6.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.6.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-1.6.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/25");
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
if (rpm_check(release:"ALA", reference:"java-1.6.0-openjdk-1.6.0.0-61.1.11.11.53.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.6.0-openjdk-debuginfo-1.6.0.0-61.1.11.11.53.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.6.0-openjdk-demo-1.6.0.0-61.1.11.11.53.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.6.0-openjdk-devel-1.6.0.0-61.1.11.11.53.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-61.1.11.11.53.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"java-1.6.0-openjdk-src-1.6.0.0-61.1.11.11.53.amzn1")) flag++;

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
