#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1009 and 
# CentOS Errata and Security Advisory 2012:1009 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(59937);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/04 14:39:51 $");

  script_cve_id("CVE-2012-1711", "CVE-2012-1713", "CVE-2012-1716", "CVE-2012-1717", "CVE-2012-1718", "CVE-2012-1719", "CVE-2012-1723", "CVE-2012-1724", "CVE-2012-1725", "CVE-2012-1726");
  script_bugtraq_id(53948);
  script_osvdb_id(82874, 82877, 82878, 82879, 82880, 82881, 82882, 82883, 82884, 82886);
  script_xref(name:"RHSA", value:"2012:1009");

  script_name(english:"CentOS 6 : java-1.7.0-openjdk (CESA-2012:1009)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.7.0-openjdk packages that fix several security issues
and one bug are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

These packages provide the OpenJDK 7 Java Runtime Environment and the
OpenJDK 7 Software Development Kit.

Multiple flaws were discovered in the CORBA (Common Object Request
Broker Architecture) implementation in Java. A malicious Java
application or applet could use these flaws to bypass Java sandbox
restrictions or modify immutable object data. (CVE-2012-1711,
CVE-2012-1719)

It was discovered that the SynthLookAndFeel class from Swing did not
properly prevent access to certain UI elements from outside the
current application context. A malicious Java application or applet
could use this flaw to crash the Java Virtual Machine, or bypass Java
sandbox restrictions. (CVE-2012-1716)

Multiple flaws were discovered in the font manager's layout lookup
implementation. A specially crafted font file could cause the Java
Virtual Machine to crash or, possibly, execute arbitrary code with the
privileges of the user running the virtual machine. (CVE-2012-1713)

Multiple flaws were found in the way the Java HotSpot Virtual Machine
verified the bytecode of the class file to be executed. A specially
crafted Java application or applet could use these flaws to crash the
Java Virtual Machine, or bypass Java sandbox restrictions.
(CVE-2012-1723, CVE-2012-1725)

It was discovered that java.lang.invoke.MethodHandles.Lookup did not
properly honor access modes. An untrusted Java application or applet
could use this flaw to bypass Java sandbox restrictions.
(CVE-2012-1726)

It was discovered that the Java XML parser did not properly handle
certain XML documents. An attacker able to make a Java application
parse a specially crafted XML file could use this flaw to make the XML
parser enter an infinite loop. (CVE-2012-1724)

It was discovered that the Java security classes did not properly
handle Certificate Revocation Lists (CRL). CRL containing entries with
duplicate certificate serial numbers could have been ignored.
(CVE-2012-1718)

It was discovered that various classes of the Java Runtime library
could create temporary files with insecure permissions. A local
attacker could use this flaw to gain access to the content of such
temporary files. (CVE-2012-1717)

This update also fixes the following bug :

* Attempting to compile a SystemTap script using the jstack tapset
could have failed with an error similar to the following :

error: the frame size of 272 bytes is larger than 256 bytes

This update corrects the jstack tapset and resolves this issue.
(BZ#833035)

This erratum also upgrades the OpenJDK package to IcedTea7 2.2.1.
Refer to the NEWS file, linked to in the References, for further
information.

All users of java-1.7.0-openjdk are advised to upgrade to these
updated packages, which resolve these issues. All running instances of
OpenJDK Java must be restarted for the update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-July/018727.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bb531a11"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.7.0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Field Bytecode Verifier Cache Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.7.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.7.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.7.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.7.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.7.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"java-1.7.0-openjdk-1.7.0.5-2.2.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.7.0-openjdk-demo-1.7.0.5-2.2.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.7.0-openjdk-devel-1.7.0.5-2.2.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.7.0-openjdk-javadoc-1.7.0.5-2.2.1.el6_3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.7.0-openjdk-src-1.7.0.5-2.2.1.el6_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
