#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0770. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66212);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2017/01/05 16:29:42 $");

  script_cve_id("CVE-2013-0401", "CVE-2013-1488", "CVE-2013-1518", "CVE-2013-1537", "CVE-2013-1557", "CVE-2013-1558", "CVE-2013-1569", "CVE-2013-2383", "CVE-2013-2384", "CVE-2013-2415", "CVE-2013-2417", "CVE-2013-2419", "CVE-2013-2420", "CVE-2013-2421", "CVE-2013-2422", "CVE-2013-2424", "CVE-2013-2426", "CVE-2013-2429", "CVE-2013-2430", "CVE-2013-2431");
  script_bugtraq_id(58504, 58507, 59131, 59141, 59153, 59159, 59165, 59166, 59167, 59170, 59179, 59184, 59187, 59190, 59194, 59206, 59212, 59219, 59228, 59243);
  script_osvdb_id(91206, 91472, 92335, 92336, 92337, 92339, 92342, 92343, 92344, 92345, 92346, 92347, 92358, 92359, 92360, 92361, 92362, 92363, 92365, 92366);
  script_xref(name:"RHSA", value:"2013:0770");

  script_name(english:"RHEL 5 / 6 : java-1.6.0-openjdk (RHSA-2013:0770)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.6.0-openjdk packages that fix various security issues
are now available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

These packages provide the OpenJDK 6 Java Runtime Environment and the
OpenJDK 6 Software Development Kit.

Multiple flaws were discovered in the font layout engine in the 2D
component. An untrusted Java application or applet could possibly use
these flaws to trigger Java Virtual Machine memory corruption.
(CVE-2013-1569, CVE-2013-2383, CVE-2013-2384)

Multiple improper permission check issues were discovered in the
Beans, Libraries, JAXP, and RMI components in OpenJDK. An untrusted
Java application or applet could use these flaws to bypass Java
sandbox restrictions. (CVE-2013-1558, CVE-2013-2422, CVE-2013-1518,
CVE-2013-1557)

The previous default value of the java.rmi.server.useCodebaseOnly
property permitted the RMI implementation to automatically load
classes from remotely specified locations. An attacker able to connect
to an application using RMI could use this flaw to make the
application execute arbitrary code. (CVE-2013-1537)

Note: The fix for CVE-2013-1537 changes the default value of the
property to true, restricting class loading to the local CLASSPATH and
locations specified in the java.rmi.server.codebase property. Refer to
Red Hat Bugzilla bug 952387 for additional details.

The 2D component did not properly process certain images. An untrusted
Java application or applet could possibly use this flaw to trigger
Java Virtual Machine memory corruption. (CVE-2013-2420)

It was discovered that the Hotspot component did not properly handle
certain intrinsic frames, and did not correctly perform MethodHandle
lookups. An untrusted Java application or applet could use these flaws
to bypass Java sandbox restrictions. (CVE-2013-2431, CVE-2013-2421)

It was discovered that JPEGImageReader and JPEGImageWriter in the
ImageIO component did not protect against modification of their state
while performing certain native code operations. An untrusted Java
application or applet could possibly use these flaws to trigger Java
Virtual Machine memory corruption. (CVE-2013-2429, CVE-2013-2430)

The JDBC driver manager could incorrectly call the toString() method
in JDBC drivers, and the ConcurrentHashMap class could incorrectly
call the defaultReadObject() method. An untrusted Java application or
applet could possibly use these flaws to bypass Java sandbox
restrictions. (CVE-2013-1488, CVE-2013-2426)

The sun.awt.datatransfer.ClassLoaderObjectInputStream class may
incorrectly invoke the system class loader. An untrusted Java
application or applet could possibly use this flaw to bypass certain
Java sandbox restrictions. (CVE-2013-0401)

Flaws were discovered in the Network component's InetAddress
serialization, and the 2D component's font handling. An untrusted Java
application or applet could possibly use these flaws to crash the Java
Virtual Machine. (CVE-2013-2417, CVE-2013-2419)

The MBeanInstantiator class implementation in the OpenJDK JMX
component did not properly check class access before creating new
instances. An untrusted Java application or applet could use this flaw
to create instances of non-public classes. (CVE-2013-2424)

It was discovered that JAX-WS could possibly create temporary files
with insecure permissions. A local attacker could use this flaw to
access temporary files created by an application using JAX-WS.
(CVE-2013-2415)

This erratum also upgrades the OpenJDK package to IcedTea6 1.11.10.
Refer to the NEWS file, linked to in the References, for further
information.

All users of java-1.6.0-openjdk are advised to upgrade to these
updated packages, which resolve these issues. All running instances of
OpenJDK Java must be restarted for the update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0401.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1488.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1518.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1537.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1557.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1558.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1569.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2383.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2384.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2415.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2417.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2419.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2420.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2421.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2422.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2424.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2426.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2429.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2430.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2431.html"
  );
  # http://icedtea.classpath.org/hg/release/icedtea6-1.11/file/icedtea6-1.11.10/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?29789070"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0770.html"
  );
  # http://icedtea.classpath.org/hg/release/icedtea6-1.11/file/icedtea6-1.11.10
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ab823eca"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Driver Manager Privileged toString() Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:0770";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.6.0-openjdk-1.6.0.0-1.40.1.11.11.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-openjdk-1.6.0.0-1.40.1.11.11.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.6.0-openjdk-debuginfo-1.6.0.0-1.40.1.11.11.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-openjdk-debuginfo-1.6.0.0-1.40.1.11.11.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.6.0-openjdk-demo-1.6.0.0-1.40.1.11.11.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-openjdk-demo-1.6.0.0-1.40.1.11.11.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.6.0-openjdk-devel-1.6.0.0-1.40.1.11.11.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-openjdk-devel-1.6.0.0-1.40.1.11.11.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-1.40.1.11.11.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-1.40.1.11.11.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.6.0-openjdk-src-1.6.0.0-1.40.1.11.11.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-openjdk-src-1.6.0.0-1.40.1.11.11.el5_9")) flag++;


  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.6.0-openjdk-1.6.0.0-1.61.1.11.11.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-openjdk-1.6.0.0-1.61.1.11.11.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.6.0-openjdk-debuginfo-1.6.0.0-1.61.1.11.11.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-openjdk-debuginfo-1.6.0.0-1.61.1.11.11.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.6.0-openjdk-demo-1.6.0.0-1.61.1.11.11.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-openjdk-demo-1.6.0.0-1.61.1.11.11.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.6.0-openjdk-devel-1.6.0.0-1.61.1.11.11.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-openjdk-devel-1.6.0.0-1.61.1.11.11.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-1.61.1.11.11.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-1.61.1.11.11.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.6.0-openjdk-src-1.6.0.0-1.61.1.11.11.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-openjdk-src-1.6.0.0-1.61.1.11.11.el6_4")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.6.0-openjdk / java-1.6.0-openjdk-debuginfo / etc");
  }
}
