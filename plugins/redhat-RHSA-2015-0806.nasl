#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0806. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82809);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/01/06 16:01:51 $");

  script_cve_id("CVE-2005-1080", "CVE-2015-0460", "CVE-2015-0469", "CVE-2015-0477", "CVE-2015-0478", "CVE-2015-0480", "CVE-2015-0488");
  script_bugtraq_id(13083, 74072, 74097, 74104, 74111, 74119, 74147);
  script_osvdb_id(15435, 120703, 120709, 120710, 120712, 120713);
  script_xref(name:"RHSA", value:"2015:0806");

  script_name(english:"RHEL 6 / 7 : java-1.7.0-openjdk (RHSA-2015:0806)");
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

Red Hat Product Security has rated this update as having Critical
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The java-1.7.0-openjdk packages provide the OpenJDK 7 Java Runtime
Environment and the OpenJDK 7 Java Software Development Kit.

An off-by-one flaw, leading to a buffer overflow, was found in the
font parsing code in the 2D component in OpenJDK. A specially crafted
font file could possibly cause the Java Virtual Machine to execute
arbitrary code, allowing an untrusted Java application or applet to
bypass Java sandbox restrictions. (CVE-2015-0469)

A flaw was found in the way the Hotspot component in OpenJDK handled
phantom references. An untrusted Java application or applet could use
this flaw to corrupt the Java Virtual Machine memory and, possibly,
execute arbitrary code, bypassing Java sandbox restrictions.
(CVE-2015-0460)

A flaw was found in the way the JSSE component in OpenJDK parsed X.509
certificate options. A specially crafted certificate could cause JSSE
to raise an exception, possibly causing an application using JSSE to
exit unexpectedly. (CVE-2015-0488)

A flaw was discovered in the Beans component in OpenJDK. An untrusted
Java application or applet could use this flaw to bypass certain Java
sandbox restrictions. (CVE-2015-0477)

A directory traversal flaw was found in the way the jar tool extracted
JAR archive files. A specially crafted JAR archive could cause jar to
overwrite arbitrary files writable by the user running jar when the
archive was extracted. (CVE-2005-1080, CVE-2015-0480)

It was found that the RSA implementation in the JCE component in
OpenJDK did not follow recommended practices for implementing RSA
signatures. (CVE-2015-0478)

The CVE-2015-0478 issue was discovered by Florian Weimer of Red Hat
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
    value:"https://www.redhat.com/security/data/cve/CVE-2005-1080.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-0460.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-0469.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-0477.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-0478.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-0480.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-0488.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-0806.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:UR");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/16");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2015:0806";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-openjdk-1.7.0.79-2.5.5.1.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-openjdk-1.7.0.79-2.5.5.1.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-openjdk-debuginfo-1.7.0.79-2.5.5.1.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-openjdk-debuginfo-1.7.0.79-2.5.5.1.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-openjdk-demo-1.7.0.79-2.5.5.1.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-openjdk-demo-1.7.0.79-2.5.5.1.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-openjdk-devel-1.7.0.79-2.5.5.1.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-openjdk-devel-1.7.0.79-2.5.5.1.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"java-1.7.0-openjdk-javadoc-1.7.0.79-2.5.5.1.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-openjdk-src-1.7.0.79-2.5.5.1.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-openjdk-src-1.7.0.79-2.5.5.1.el6_6")) flag++;


  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.7.0-openjdk-1.7.0.79-2.5.5.1.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-1.7.0.79-2.5.5.1.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.7.0-openjdk-accessibility-1.7.0.79-2.5.5.1.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-accessibility-1.7.0.79-2.5.5.1.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.7.0-openjdk-debuginfo-1.7.0.79-2.5.5.1.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-debuginfo-1.7.0.79-2.5.5.1.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.7.0-openjdk-demo-1.7.0.79-2.5.5.1.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-demo-1.7.0.79-2.5.5.1.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.7.0-openjdk-devel-1.7.0.79-2.5.5.1.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-devel-1.7.0.79-2.5.5.1.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.7.0-openjdk-headless-1.7.0.79-2.5.5.1.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-headless-1.7.0.79-2.5.5.1.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"java-1.7.0-openjdk-javadoc-1.7.0.79-2.5.5.1.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.7.0-openjdk-src-1.7.0.79-2.5.5.1.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-src-1.7.0.79-2.5.5.1.el7_1")) flag++;


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
