#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0967. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34751);
  script_version ("$Revision: 1.21 $");
  script_cvs_date("$Date: 2017/01/03 17:16:34 $");

  script_cve_id("CVE-2008-2364", "CVE-2008-2939");
  script_bugtraq_id(29653, 30560);
  script_xref(name:"RHSA", value:"2008:0967");

  script_name(english:"RHEL 3 / 4 / 5 : httpd (RHSA-2008:0967)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated httpd packages that resolve several security issues and fix a
bug are now available for Red Hat Enterprise Linux 3, 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The Apache HTTP Server is a popular Web server.

A flaw was found in the mod_proxy Apache module. An attacker in
control of a Web server to which requests were being proxied could
have caused a limited denial of service due to CPU consumption and
stack exhaustion. (CVE-2008-2364)

A flaw was found in the mod_proxy_ftp Apache module. If Apache was
configured to support FTP-over-HTTP proxying, a remote attacker could
have performed a cross-site scripting attack. (CVE-2008-2939)

In addition, these updated packages fix a bug found in the handling of
the 'ProxyRemoteMatch' directive in the Red Hat Enterprise Linux 4
httpd packages. This bug is not present in the Red Hat Enterprise
Linux 3 or Red Hat Enterprise Linux 5 packages.

Users of httpd should upgrade to these updated packages, which contain
backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-2364.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-2939.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2008-0967.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-suexec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/11/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x / 4.x / 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2008:0967";
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
  if (rpm_check(release:"RHEL3", reference:"httpd-2.0.46-71.ent")) flag++;

  if (rpm_check(release:"RHEL3", reference:"httpd-devel-2.0.46-71.ent")) flag++;

  if (rpm_check(release:"RHEL3", reference:"mod_ssl-2.0.46-71.ent")) flag++;


  if (rpm_check(release:"RHEL4", reference:"httpd-2.0.52-41.ent.2")) flag++;

  if (rpm_check(release:"RHEL4", reference:"httpd-devel-2.0.52-41.ent.2")) flag++;

  if (rpm_check(release:"RHEL4", reference:"httpd-manual-2.0.52-41.ent.2")) flag++;

  if (rpm_check(release:"RHEL4", reference:"httpd-suexec-2.0.52-41.ent.2")) flag++;

  if (rpm_check(release:"RHEL4", reference:"mod_ssl-2.0.52-41.ent.2")) flag++;


  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"httpd-2.2.3-11.el5_2.4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"httpd-2.2.3-11.el5_2.4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"httpd-2.2.3-11.el5_2.4")) flag++;

  if (rpm_check(release:"RHEL5", reference:"httpd-devel-2.2.3-11.el5_2.4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"httpd-manual-2.2.3-11.el5_2.4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"httpd-manual-2.2.3-11.el5_2.4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"httpd-manual-2.2.3-11.el5_2.4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"mod_ssl-2.2.3-11.el5_2.4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"mod_ssl-2.2.3-11.el5_2.4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"mod_ssl-2.2.3-11.el5_2.4")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd / httpd-devel / httpd-manual / httpd-suexec / mod_ssl");
  }
}
