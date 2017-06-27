#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0675. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76889);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/01/06 15:40:57 $");

  script_cve_id("CVE-2014-0429", "CVE-2014-0446", "CVE-2014-0451", "CVE-2014-0452", "CVE-2014-0453", "CVE-2014-0454", "CVE-2014-0455", "CVE-2014-0456", "CVE-2014-0457", "CVE-2014-0458", "CVE-2014-0459", "CVE-2014-0460", "CVE-2014-0461", "CVE-2014-1876", "CVE-2014-2397", "CVE-2014-2398", "CVE-2014-2402", "CVE-2014-2403", "CVE-2014-2412", "CVE-2014-2413", "CVE-2014-2414", "CVE-2014-2421", "CVE-2014-2423", "CVE-2014-2427");
  script_bugtraq_id(65568, 66856, 66866, 66873, 66877, 66879, 66881, 66883, 66887, 66891, 66893, 66894, 66898, 66899, 66902, 66903, 66905, 66909, 66910, 66914, 66916, 66917, 66918, 66920);
  script_xref(name:"RHSA", value:"2014:0675");

  script_name(english:"RHEL 7 : java-1.7.0-openjdk (RHSA-2014:0675)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.7.0-openjdk packages that fix various security issues
are now available for Red Hat Enterprise Linux 7.

The Red Hat Security Response Team has rated this update as having
Critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The java-1.7.0-openjdk packages provide the OpenJDK 7 Java Runtime
Environment and the OpenJDK 7 Java Software Development Kit.

An input validation flaw was discovered in the medialib library in the
2D component. A specially crafted image could trigger Java Virtual
Machine memory corruption when processed. A remote attacker, or an
untrusted Java application or applet, could possibly use this flaw to
execute arbitrary code with the privileges of the user running the
Java Virtual Machine. (CVE-2014-0429)

Multiple flaws were discovered in the Hotspot and 2D components in
OpenJDK. An untrusted Java application or applet could use these flaws
to trigger Java Virtual Machine memory corruption and possibly bypass
Java sandbox restrictions. (CVE-2014-0456, CVE-2014-2397,
CVE-2014-2421)

Multiple improper permission check issues were discovered in the
Libraries component in OpenJDK. An untrusted Java application or
applet could use these flaws to bypass Java sandbox restrictions.
(CVE-2014-0457, CVE-2014-0455, CVE-2014-0461)

Multiple improper permission check issues were discovered in the AWT,
JAX-WS, JAXB, Libraries, Security, Sound, and 2D components in
OpenJDK. An untrusted Java application or applet could use these flaws
to bypass certain Java sandbox restrictions. (CVE-2014-2412,
CVE-2014-0451, CVE-2014-0458, CVE-2014-2423, CVE-2014-0452,
CVE-2014-2414, CVE-2014-2402, CVE-2014-0446, CVE-2014-2413,
CVE-2014-0454, CVE-2014-2427, CVE-2014-0459)

Multiple flaws were identified in the Java Naming and Directory
Interface (JNDI) DNS client. These flaws could make it easier for a
remote attacker to perform DNS spoofing attacks. (CVE-2014-0460)

It was discovered that the JAXP component did not properly prevent
access to arbitrary files when a SecurityManager was present. This
flaw could cause a Java application using JAXP to leak sensitive
information, or affect application availability. (CVE-2014-2403)

It was discovered that the Security component in OpenJDK could leak
some timing information when performing PKCS#1 unpadding. This could
possibly lead to the disclosure of some information that was meant to
be protected by encryption. (CVE-2014-0453)

It was discovered that the fix for CVE-2013-5797 did not properly
resolve input sanitization flaws in javadoc. When javadoc
documentation was generated from an untrusted Java source code and
hosted on a domain not controlled by the code author, these issues
could make it easier to perform cross-site scripting (XSS) attacks.
(CVE-2014-2398)

An insecure temporary file use flaw was found in the way the unpack200
utility created log files. A local attacker could possibly use this
flaw to perform a symbolic link attack and overwrite arbitrary files
with the privileges of the user running unpack200. (CVE-2014-1876)

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
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0429.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0446.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0451.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0452.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0453.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0454.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0455.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0456.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0457.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0458.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0459.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0460.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0461.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-1876.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-2397.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-2398.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-2402.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-2403.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-2412.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-2413.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-2414.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-2421.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-2423.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-2427.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-0675.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/30");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:0675";
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
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.7.0-openjdk-1.7.0.55-2.4.7.2.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-1.7.0.55-2.4.7.2.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.7.0-openjdk-accessibility-1.7.0.55-2.4.7.2.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-accessibility-1.7.0.55-2.4.7.2.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.7.0-openjdk-debuginfo-1.7.0.55-2.4.7.2.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-debuginfo-1.7.0.55-2.4.7.2.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.7.0-openjdk-demo-1.7.0.55-2.4.7.2.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-demo-1.7.0.55-2.4.7.2.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.7.0-openjdk-devel-1.7.0.55-2.4.7.2.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-devel-1.7.0.55-2.4.7.2.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.7.0-openjdk-headless-1.7.0.55-2.4.7.2.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-headless-1.7.0.55-2.4.7.2.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", reference:"java-1.7.0-openjdk-javadoc-1.7.0.55-2.4.7.2.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.7.0-openjdk-src-1.7.0.55-2.4.7.2.el7_0")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-src-1.7.0.55-2.4.7.2.el7_0")) flag++;

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
