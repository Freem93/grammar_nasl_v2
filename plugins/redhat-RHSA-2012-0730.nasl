#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0730. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59490);
  script_version ("$Revision: 1.20 $");
  script_cvs_date("$Date: 2017/01/05 16:04:22 $");

  script_cve_id("CVE-2012-1711", "CVE-2012-1713", "CVE-2012-1716", "CVE-2012-1717", "CVE-2012-1718", "CVE-2012-1719", "CVE-2012-1723", "CVE-2012-1724", "CVE-2012-1725");
  script_osvdb_id(82874, 82877, 82878, 82879, 82880, 82882, 82883, 82884, 82886);
  script_xref(name:"RHSA", value:"2012:0730");

  script_name(english:"RHEL 5 : java-1.6.0-openjdk (RHSA-2012:0730)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.6.0-openjdk packages that fix several security issues
are now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

These packages provide the OpenJDK 6 Java Runtime Environment and the
OpenJDK 6 Software Development Kit.

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

This erratum also upgrades the OpenJDK package to IcedTea6 1.10.8.
Refer to the NEWS file, linked to in the References, for further
information.

All users of java-1.6.0-openjdk are advised to upgrade to these
updated packages, which resolve these issues. All running instances of
OpenJDK Java must be restarted for the update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-1711.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-1713.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-1716.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-1717.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-1718.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-1719.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-1723.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-1724.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-1725.html"
  );
  # http://icedtea.classpath.org/hg/release/icedtea6-1.10/file/icedtea6-1.10.8/NEWS
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4dcca205"
  );
  # http://www.oracle.com/technetwork/topics/security/javacpujun2012-1515912.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7760536b"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-0730.html"
  );
  # http://icedtea.classpath.org/hg/release/icedtea6-1.10/file/icedtea6-1.10.8/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?88aaea09"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.oracle.com/technetwork/topics/security/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Field Bytecode Verifier Cache Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2012:0730";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.6.0-openjdk-1.6.0.0-1.27.1.10.8.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-openjdk-1.6.0.0-1.27.1.10.8.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.6.0-openjdk-debuginfo-1.6.0.0-1.27.1.10.8.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-openjdk-debuginfo-1.6.0.0-1.27.1.10.8.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.6.0-openjdk-demo-1.6.0.0-1.27.1.10.8.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-openjdk-demo-1.6.0.0-1.27.1.10.8.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.6.0-openjdk-devel-1.6.0.0-1.27.1.10.8.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-openjdk-devel-1.6.0.0-1.27.1.10.8.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-1.27.1.10.8.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-1.27.1.10.8.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.6.0-openjdk-src-1.6.0.0-1.27.1.10.8.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-openjdk-src-1.6.0.0-1.27.1.10.8.el5_8")) flag++;

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
