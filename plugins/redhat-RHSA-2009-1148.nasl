#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1148. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39770);
  script_version ("$Revision: 1.26 $");
  script_cvs_date("$Date: 2017/01/03 17:27:02 $");

  script_cve_id("CVE-2009-1890", "CVE-2009-1891");
  script_bugtraq_id(35565);
  script_osvdb_id(55782);
  script_xref(name:"RHSA", value:"2009:1148");

  script_name(english:"RHEL 5 : httpd (RHSA-2009:1148)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated httpd packages that fix two security issues are now available
for Red Hat Enterprise Linux 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The Apache HTTP Server is a popular Web server.

A denial of service flaw was found in the Apache mod_proxy module when
it was used as a reverse proxy. A remote attacker could use this flaw
to force a proxy process to consume large amounts of CPU time.
(CVE-2009-1890)

A denial of service flaw was found in the Apache mod_deflate module.
This module continued to compress large files until compression was
complete, even if the network connection that requested the content
was closed before compression completed. This would cause mod_deflate
to consume large amounts of CPU if mod_deflate was enabled for a large
file. (CVE-2009-1891)

All httpd users should upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the updated packages, the httpd daemon must be restarted for the
update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-1890.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-1891.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2009-1148.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2009:1148";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"httpd-2.2.3-22.el5_3.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"httpd-2.2.3-22.el5_3.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"httpd-2.2.3-22.el5_3.2")) flag++;

  if (rpm_check(release:"RHEL5", reference:"httpd-devel-2.2.3-22.el5_3.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"httpd-manual-2.2.3-22.el5_3.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"httpd-manual-2.2.3-22.el5_3.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"httpd-manual-2.2.3-22.el5_3.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"mod_ssl-2.2.3-22.el5_3.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"mod_ssl-2.2.3-22.el5_3.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"mod_ssl-2.2.3-22.el5_3.2")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd / httpd-devel / httpd-manual / mod_ssl");
  }
}
