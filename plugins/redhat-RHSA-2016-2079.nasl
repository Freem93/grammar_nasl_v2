#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:2079. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94150);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2017/01/10 20:46:33 $");

  script_cve_id("CVE-2016-5542", "CVE-2016-5554", "CVE-2016-5573", "CVE-2016-5582", "CVE-2016-5597");
  script_osvdb_id(145946, 145947, 145948, 145949, 145950);
  script_xref(name:"RHSA", value:"2016:2079");

  script_name(english:"RHEL 6 / 7 : java-1.8.0-openjdk (RHSA-2016:2079)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for java-1.8.0-openjdk is now available for Red Hat
Enterprise Linux 6 and Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Critical. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The java-1.8.0-openjdk packages provide the OpenJDK 8 Java Runtime
Environment and the OpenJDK 8 Java Software Development Kit.

Security Fix(es) :

* It was discovered that the Hotspot component of OpenJDK did not
properly check arguments of the System.arraycopy() function in certain
cases. An untrusted Java application or applet could use this flaw to
corrupt virtual machine's memory and completely bypass Java sandbox
restrictions. (CVE-2016-5582)

* It was discovered that the Hotspot component of OpenJDK did not
properly check received Java Debug Wire Protocol (JDWP) packets. An
attacker could possibly use this flaw to send debugging commands to a
Java program running with debugging enabled if they could make
victim's browser send HTTP requests to the JDWP port of the debugged
application. (CVE-2016-5573)

* It was discovered that the Libraries component of OpenJDK did not
restrict the set of algorithms used for Jar integrity verification.
This flaw could allow an attacker to modify content of the Jar file
that used weak signing key or hash algorithm. (CVE-2016-5542)

Note: After this update, MD2 hash algorithm and RSA keys with less
than 1024 bits are no longer allowed to be used for Jar integrity
verification by default. MD5 hash algorithm is expected to be disabled
by default in the future updates. A newly introduced security property
jdk.jar.disabledAlgorithms can be used to control the set of disabled
algorithms.

* A flaw was found in the way the JMX component of OpenJDK handled
classloaders. An untrusted Java application or applet could use this
flaw to bypass certain Java sandbox restrictions. (CVE-2016-5554)

* A flaw was found in the way the Networking component of OpenJDK
handled HTTP proxy authentication. A Java application could possibly
expose HTTPS server authentication credentials via a plain text
network connection to an HTTP proxy if proxy asked for authentication.
(CVE-2016-5597)

Note: After this update, Basic HTTP proxy authentication can no longer
be used when tunneling HTTPS connection through an HTTP proxy. Newly
introduced system properties jdk.http.auth.proxying.disabledSchemes
and jdk.http.auth.tunneling.disabledSchemes can be used to control
which authentication schemes can be requested by an HTTP proxy when
proxying HTTP and HTTPS connections respectively.

Note: If the web browser plug-in provided by the icedtea-web package
was installed, the issues exposed via Java applets could have been
exploited without user interaction if a user visited a malicious
website."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-5542.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-5554.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-5573.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-5582.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-5597.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2016-2079.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-accessibility-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-demo-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-devel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-headless-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-javadoc-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-openjdk-src-debug");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2016:2079";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.8.0-openjdk-1.8.0.111-0.b15.el6_8")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.8.0-openjdk-1.8.0.111-0.b15.el6_8")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.8.0-openjdk-debug-1.8.0.111-0.b15.el6_8")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.8.0-openjdk-debug-1.8.0.111-0.b15.el6_8")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.8.0-openjdk-debuginfo-1.8.0.111-0.b15.el6_8")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.8.0-openjdk-debuginfo-1.8.0.111-0.b15.el6_8")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.8.0-openjdk-demo-1.8.0.111-0.b15.el6_8")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.8.0-openjdk-demo-1.8.0.111-0.b15.el6_8")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.8.0-openjdk-demo-debug-1.8.0.111-0.b15.el6_8")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.8.0-openjdk-demo-debug-1.8.0.111-0.b15.el6_8")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.8.0-openjdk-devel-1.8.0.111-0.b15.el6_8")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.8.0-openjdk-devel-1.8.0.111-0.b15.el6_8")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.8.0-openjdk-devel-debug-1.8.0.111-0.b15.el6_8")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.8.0-openjdk-devel-debug-1.8.0.111-0.b15.el6_8")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.8.0-openjdk-headless-1.8.0.111-0.b15.el6_8")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.8.0-openjdk-headless-1.8.0.111-0.b15.el6_8")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.8.0-openjdk-headless-debug-1.8.0.111-0.b15.el6_8")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.8.0-openjdk-headless-debug-1.8.0.111-0.b15.el6_8")) flag++;

  if (rpm_check(release:"RHEL6", reference:"java-1.8.0-openjdk-javadoc-1.8.0.111-0.b15.el6_8")) flag++;

  if (rpm_check(release:"RHEL6", reference:"java-1.8.0-openjdk-javadoc-debug-1.8.0.111-0.b15.el6_8")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.8.0-openjdk-src-1.8.0.111-0.b15.el6_8")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.8.0-openjdk-src-1.8.0.111-0.b15.el6_8")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.8.0-openjdk-src-debug-1.8.0.111-0.b15.el6_8")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.8.0-openjdk-src-debug-1.8.0.111-0.b15.el6_8")) flag++;


  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.8.0-openjdk-1.8.0.111-1.b15.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-1.8.0.111-1.b15.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.8.0-openjdk-accessibility-1.8.0.111-1.b15.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-accessibility-1.8.0.111-1.b15.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-accessibility-debug-1.8.0.111-1.b15.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-debug-1.8.0.111-1.b15.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.8.0-openjdk-debuginfo-1.8.0.111-1.b15.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-debuginfo-1.8.0.111-1.b15.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.8.0-openjdk-demo-1.8.0.111-1.b15.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-demo-1.8.0.111-1.b15.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-demo-debug-1.8.0.111-1.b15.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.8.0-openjdk-devel-1.8.0.111-1.b15.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-devel-1.8.0.111-1.b15.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-devel-debug-1.8.0.111-1.b15.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.8.0-openjdk-headless-1.8.0.111-1.b15.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-headless-1.8.0.111-1.b15.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-headless-debug-1.8.0.111-1.b15.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", reference:"java-1.8.0-openjdk-javadoc-1.8.0.111-1.b15.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", reference:"java-1.8.0-openjdk-javadoc-debug-1.8.0.111-1.b15.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.8.0-openjdk-src-1.8.0.111-1.b15.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-src-1.8.0.111-1.b15.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-src-debug-1.8.0.111-1.b15.el7_2")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.8.0-openjdk / java-1.8.0-openjdk-accessibility / etc");
  }
}
