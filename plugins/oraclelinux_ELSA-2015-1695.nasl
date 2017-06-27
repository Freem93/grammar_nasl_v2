#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:1695 and 
# Oracle Linux Security Advisory ELSA-2015-1695 respectively.
#

include("compat.inc");

if (description)
{
  script_id(85711);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2017/01/27 23:31:26 $");

  script_cve_id("CVE-2015-0254");
  script_osvdb_id(118922);
  script_xref(name:"RHSA", value:"2015:1695");

  script_name(english:"Oracle Linux 6 / 7 : jakarta-taglibs-standard (ELSA-2015-1695)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2015:1695 :

Updated jakarta-taglibs-standard packages that fix one security issue
are now available for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Important
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

jakarta-taglibs-standard is the Java Standard Tag Library (JSTL). This
library is used in conjunction with Tomcat and Java Server Pages
(JSP).

It was found that the Java Standard Tag Library (JSTL) allowed the
processing of untrusted XML documents to utilize external entity
references, which could access resources on the host system and,
potentially, allowing arbitrary code execution. (CVE-2015-0254)

Note: jakarta-taglibs-standard users may need to take additional steps
after applying this update. Detailed instructions on the additional
steps can be found here :

https://access.redhat.com/solutions/1584363

All jakarta-taglibs-standard users are advised to upgrade to these
updated packages, which contain a backported patch to correct this
issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-August/005375.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-August/005377.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected jakarta-taglibs-standard packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:jakarta-taglibs-standard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:jakarta-taglibs-standard-javadoc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6 / 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"jakarta-taglibs-standard-1.1.1-11.7.el6_7")) flag++;
if (rpm_check(release:"EL6", reference:"jakarta-taglibs-standard-javadoc-1.1.1-11.7.el6_7")) flag++;

if (rpm_check(release:"EL7", cpu:"x86_64", reference:"jakarta-taglibs-standard-1.1.2-14.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"jakarta-taglibs-standard-javadoc-1.1.2-14.el7_1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jakarta-taglibs-standard / jakarta-taglibs-standard-javadoc");
}
