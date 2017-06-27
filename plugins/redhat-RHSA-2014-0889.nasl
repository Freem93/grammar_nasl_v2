#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0889. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76515);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/01/06 15:40:58 $");

  script_cve_id("CVE-2014-2483", "CVE-2014-2490", "CVE-2014-4209", "CVE-2014-4216", "CVE-2014-4218", "CVE-2014-4219", "CVE-2014-4221", "CVE-2014-4223", "CVE-2014-4244", "CVE-2014-4252", "CVE-2014-4262", "CVE-2014-4263", "CVE-2014-4266");
  script_osvdb_id(109125, 109126, 109127, 109129, 109130, 109131, 109132, 109135, 109136, 109137, 109140, 109141, 109142);
  script_xref(name:"RHSA", value:"2014:0889");

  script_name(english:"RHEL 6 / 7 : java-1.7.0-openjdk (RHSA-2014:0889)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.7.0-openjdk packages that fix multiple security issues
are now available for Red Hat Enterprise Linux 6 and 7.

The Red Hat Security Response Team has rated this update as having
Critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The java-1.7.0-openjdk packages provide the OpenJDK 7 Java Runtime
Environment and the OpenJDK 7 Java Software Development Kit.

It was discovered that the Hotspot component in OpenJDK did not
properly verify bytecode from the class files. An untrusted Java
application or applet could possibly use these flaws to bypass Java
sandbox restrictions. (CVE-2014-4216, CVE-2014-4219)

A format string flaw was discovered in the Hotspot component event
logger in OpenJDK. An untrusted Java application or applet could use
this flaw to crash the Java Virtual Machine or, potentially, execute
arbitrary code with the privileges of the Java Virtual Machine.
(CVE-2014-2490)

Multiple improper permission check issues were discovered in the
Libraries component in OpenJDK. An untrusted Java application or
applet could use these flaws to bypass Java sandbox restrictions.
(CVE-2014-4223, CVE-2014-4262, CVE-2014-2483)

Multiple flaws were discovered in the JMX, Libraries, Security, and
Serviceability components in OpenJDK. An untrusted Java application or
applet could use these flaws to bypass certain Java sandbox
restrictions. (CVE-2014-4209, CVE-2014-4218, CVE-2014-4221,
CVE-2014-4252, CVE-2014-4266)

It was discovered that the RSA algorithm in the Security component in
OpenJDK did not sufficiently perform blinding while performing
operations that were using private keys. An attacker able to measure
timing differences of those operations could possibly leak information
about the used keys. (CVE-2014-4244)

The Diffie-Hellman (DH) key exchange algorithm implementation in the
Security component in OpenJDK failed to validate public DH parameters
properly. This could cause OpenJDK to accept and use weak parameters,
allowing an attacker to recover the negotiated key. (CVE-2014-4263)

The CVE-2014-4262 issue was discovered by Florian Weimer of Red Hat
Product Security.

Note: If the web browser plug-in provided by the icedtea-web package
was installed, the issues exposed via Java applets could have been
exploited without user interaction if a user visited a malicious
website.

All users of java-1.7.0-openjdk are advised to upgrade to these
updated packages, which resolve these issues. All running instances of
OpenJDK Java must be restarted for the update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-2483.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-2490.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-4209.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-4216.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-4218.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-4219.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-4221.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-4223.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-4244.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-4252.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-4262.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-4263.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-4266.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-0889.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x / 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:0889";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-openjdk-1.7.0.65-2.5.1.2.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-openjdk-1.7.0.65-2.5.1.2.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-openjdk-debuginfo-1.7.0.65-2.5.1.2.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-openjdk-debuginfo-1.7.0.65-2.5.1.2.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-openjdk-demo-1.7.0.65-2.5.1.2.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-openjdk-demo-1.7.0.65-2.5.1.2.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-openjdk-devel-1.7.0.65-2.5.1.2.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-openjdk-devel-1.7.0.65-2.5.1.2.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"java-1.7.0-openjdk-javadoc-1.7.0.65-2.5.1.2.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-openjdk-src-1.7.0.65-2.5.1.2.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-openjdk-src-1.7.0.65-2.5.1.2.el6_5")) flag++;


  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.7.0-openjdk-1.7.0.65-2.5.1.2.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-1.7.0.65-2.5.1.2.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.7.0-openjdk-accessibility-1.7.0.65-2.5.1.2.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-accessibility-1.7.0.65-2.5.1.2.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.7.0-openjdk-debuginfo-1.7.0.65-2.5.1.2.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-debuginfo-1.7.0.65-2.5.1.2.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.7.0-openjdk-demo-1.7.0.65-2.5.1.2.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-demo-1.7.0.65-2.5.1.2.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.7.0-openjdk-devel-1.7.0.65-2.5.1.2.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-devel-1.7.0.65-2.5.1.2.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.7.0-openjdk-headless-1.7.0.65-2.5.1.2.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-headless-1.7.0.65-2.5.1.2.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", reference:"java-1.7.0-openjdk-javadoc-1.7.0.65-2.5.1.2.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.7.0-openjdk-src-1.7.0.65-2.5.1.2.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-src-1.7.0.65-2.5.1.2.el7_0")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.7.0-openjdk / java-1.7.0-openjdk-accessibility / etc");
  }
}
