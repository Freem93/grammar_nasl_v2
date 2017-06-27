#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2016:1776 and 
# Oracle Linux Security Advisory ELSA-2016-1776 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(93147);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/12/07 21:08:17 $");

  script_cve_id("CVE-2016-3458", "CVE-2016-3500", "CVE-2016-3508", "CVE-2016-3550", "CVE-2016-3606");
  script_osvdb_id(141825, 141832, 141833, 141834, 141835);
  script_xref(name:"RHSA", value:"2016:1776");

  script_name(english:"Oracle Linux 5 / 6 / 7 : java-1.6.0-openjdk (ELSA-2016-1776)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2016:1776 :

An update for java-1.6.0-openjdk is now available for Red Hat
Enterprise Linux 5, Red Hat Enterprise Linux 6, and Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The java-1.6.0-openjdk packages provide the OpenJDK 6 Java Runtime
Environment and the OpenJDK 6 Java Software Development Kit.

Security Fix(es) :

* An insufficient bytecode verification flaw was discovered in the
Hotspot component in OpenJDK. An untrusted Java application or applet
could use this flaw to completely bypass Java sandbox restrictions.
(CVE-2016-3606)

* Multiple denial of service flaws were found in the JAXP component in
OpenJDK. A specially crafted XML file could cause a Java application
using JAXP to consume an excessive amount of CPU and memory when
parsed. (CVE-2016-3500, CVE-2016-3508)

* Multiple flaws were found in the CORBA and Hotsport components in
OpenJDK. An untrusted Java application or applet could use these flaws
to bypass certain Java sandbox restrictions. (CVE-2016-3458,
CVE-2016-3550)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-August/006297.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-August/006298.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-August/006299.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.6.0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.6.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.6.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.6.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.6.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^(5|6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5 / 6 / 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"java-1.6.0-openjdk-1.6.0.40-1.13.12.4.0.1.el5_11")) flag++;
if (rpm_check(release:"EL5", reference:"java-1.6.0-openjdk-demo-1.6.0.40-1.13.12.4.0.1.el5_11")) flag++;
if (rpm_check(release:"EL5", reference:"java-1.6.0-openjdk-devel-1.6.0.40-1.13.12.4.0.1.el5_11")) flag++;
if (rpm_check(release:"EL5", reference:"java-1.6.0-openjdk-javadoc-1.6.0.40-1.13.12.4.0.1.el5_11")) flag++;
if (rpm_check(release:"EL5", reference:"java-1.6.0-openjdk-src-1.6.0.40-1.13.12.4.0.1.el5_11")) flag++;

if (rpm_check(release:"EL6", reference:"java-1.6.0-openjdk-1.6.0.40-1.13.12.6.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"java-1.6.0-openjdk-demo-1.6.0.40-1.13.12.6.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"java-1.6.0-openjdk-devel-1.6.0.40-1.13.12.6.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"java-1.6.0-openjdk-javadoc-1.6.0.40-1.13.12.6.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"java-1.6.0-openjdk-src-1.6.0.40-1.13.12.6.el6_8")) flag++;

if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.6.0-openjdk-1.6.0.40-1.13.12.5.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.6.0-openjdk-demo-1.6.0.40-1.13.12.5.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.6.0-openjdk-devel-1.6.0.40-1.13.12.5.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.6.0-openjdk-javadoc-1.6.0.40-1.13.12.5.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.6.0-openjdk-src-1.6.0.40-1.13.12.5.el7_2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.6.0-openjdk / java-1.6.0-openjdk-demo / etc");
}
