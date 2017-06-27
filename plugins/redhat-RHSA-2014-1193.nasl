#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1193. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77695);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/01/06 15:50:59 $");

  script_cve_id("CVE-2014-3596");
  script_bugtraq_id(69295);
  script_osvdb_id(87150);
  script_xref(name:"RHSA", value:"2014:1193");

  script_name(english:"RHEL 5 / 6 : axis (RHSA-2014:1193)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated axis packages that fix one security issue are now available
for Red Hat Enterprise Linux 5 and 6.

Red Hat Product Security has rated this update as having Important
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Apache Axis is an implementation of SOAP (Simple Object Access
Protocol). It can be used to build both web service clients and
servers.

It was discovered that Axis incorrectly extracted the host name from
an X.509 certificate subject's Common Name (CN) field. A
man-in-the-middle attacker could use this flaw to spoof an SSL server
using a specially crafted X.509 certificate. (CVE-2014-3596)

For additional information on this flaw, refer to the Knowledgebase
article in the References section.

This issue was discovered by David Jorm and Arun Neelicattu of Red Hat
Product Security.

All axis users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. Applications using
Apache Axis must be restarted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-3596.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/solutions/1164433"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-1193.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:axis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:axis-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:axis-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:axis-manual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.5");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/16");
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
if (! ereg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:1193";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"axis-1.2.1-2jpp.8.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"axis-1.2.1-2jpp.8.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"axis-1.2.1-2jpp.8.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"axis-debuginfo-1.2.1-2jpp.8.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"axis-debuginfo-1.2.1-2jpp.8.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"axis-debuginfo-1.2.1-2jpp.8.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"axis-javadoc-1.2.1-2jpp.8.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"axis-javadoc-1.2.1-2jpp.8.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"axis-javadoc-1.2.1-2jpp.8.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"axis-manual-1.2.1-2jpp.8.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"axis-manual-1.2.1-2jpp.8.el5_10")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"axis-manual-1.2.1-2jpp.8.el5_10")) flag++;


  if (rpm_check(release:"RHEL6", reference:"axis-1.2.1-7.5.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"axis-javadoc-1.2.1-7.5.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"axis-manual-1.2.1-7.5.el6_5")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "axis / axis-debuginfo / axis-javadoc / axis-manual");
  }
}
