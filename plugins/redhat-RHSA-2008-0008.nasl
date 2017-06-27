#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0008. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29977);
  script_version ("$Revision: 1.22 $");
  script_cvs_date("$Date: 2017/01/30 15:10:03 $");

  script_cve_id("CVE-2007-4465", "CVE-2007-5000", "CVE-2007-6388", "CVE-2007-6421", "CVE-2007-6422", "CVE-2008-0005");
  script_bugtraq_id(25653, 26838, 27234, 27236, 27237);
  script_osvdb_id(40262, 40263, 40264, 42214);
  script_xref(name:"RHSA", value:"2008:0008");

  script_name(english:"RHEL 5 : httpd (RHSA-2008:0008)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Apache httpd packages that fix several security issues are now
available for Red Hat Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The Apache HTTP Server is a popular Web server.

A flaw was found in the mod_imagemap module. On sites where
mod_imagemap was enabled and an imagemap file was publicly available,
a cross-site scripting attack was possible. (CVE-2007-5000)

A flaw was found in the mod_autoindex module. On sites where directory
listings are used, and the 'AddDefaultCharset' directive has been
removed from the configuration, a cross-site scripting attack might
have been possible against Web browsers which do not correctly derive
the response character set following the rules in RFC 2616.
(CVE-2007-4465)

A flaw was found in the mod_status module. On sites where mod_status
was enabled and the status pages were publicly available, a cross-site
scripting attack was possible. (CVE-2007-6388)

A flaw was found in the mod_proxy_balancer module. On sites where
mod_proxy_balancer was enabled, a cross-site scripting attack against
an authorized user was possible. (CVE-2007-6421)

A flaw was found in the mod_proxy_balancer module. On sites where
mod_proxy_balancer was enabled, an authorized user could send a
carefully crafted request that would cause the Apache child process
handling that request to crash. This could lead to a denial of service
if using a threaded Multi-Processing Module. (CVE-2007-6422)

A flaw was found in the mod_proxy_ftp module. On sites where
mod_proxy_ftp was enabled and a forward proxy was configured, a
cross-site scripting attack was possible against Web browsers which do
not correctly derive the response character set following the rules in
RFC 2616. (CVE-2008-0005)

Users of Apache httpd should upgrade to these updated packages, which
contain backported patches to resolve these issues. Users should
restart httpd after installing this update."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-4465.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-5000.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-6388.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-6421.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-6422.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-0005.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2008-0008.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/15");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2008:0008";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"httpd-2.2.3-11.el5_1.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"httpd-2.2.3-11.el5_1.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"httpd-2.2.3-11.el5_1.3")) flag++;

  if (rpm_check(release:"RHEL5", reference:"httpd-devel-2.2.3-11.el5_1.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"httpd-manual-2.2.3-11.el5_1.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"httpd-manual-2.2.3-11.el5_1.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"httpd-manual-2.2.3-11.el5_1.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"mod_ssl-2.2.3-11.el5_1.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"mod_ssl-2.2.3-11.el5_1.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"mod_ssl-2.2.3-11.el5_1.3")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd / httpd-devel / httpd-manual / mod_ssl");
  }
}
