#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2008:0967 and 
# Oracle Linux Security Advisory ELSA-2008-0967 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67760);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/07 20:57:50 $");

  script_cve_id("CVE-2008-2364", "CVE-2008-2939");
  script_bugtraq_id(29653, 30560);
  script_xref(name:"RHSA", value:"2008:0967");

  script_name(english:"Oracle Linux 3 / 4 / 5 : httpd (ELSA-2008-0967)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2008:0967 :

Updated httpd packages that resolve several security issues and fix a
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
    value:"https://oss.oracle.com/pipermail/el-errata/2008-November/000795.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2008-November/000796.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2008-November/000797.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected httpd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpd-suexec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 3 / 4 / 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL3", cpu:"i386", reference:"httpd-2.0.46-71.ent.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"httpd-2.0.46-71.ent.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"httpd-devel-2.0.46-71.ent.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"httpd-devel-2.0.46-71.ent.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"mod_ssl-2.0.46-71.ent.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"mod_ssl-2.0.46-71.ent.0.1")) flag++;

if (rpm_check(release:"EL4", reference:"httpd-2.0.52-41.ent.2.0.1")) flag++;
if (rpm_check(release:"EL4", reference:"httpd-devel-2.0.52-41.ent.2.0.1")) flag++;
if (rpm_check(release:"EL4", reference:"httpd-manual-2.0.52-41.ent.2.0.1")) flag++;
if (rpm_check(release:"EL4", reference:"httpd-suexec-2.0.52-41.ent.2.0.1")) flag++;
if (rpm_check(release:"EL4", reference:"mod_ssl-2.0.52-41.ent.2.0.1")) flag++;

if (rpm_check(release:"EL5", reference:"httpd-2.2.3-11.0.1.el5_2.4")) flag++;
if (rpm_check(release:"EL5", reference:"httpd-devel-2.2.3-11.0.1.el5_2.4")) flag++;
if (rpm_check(release:"EL5", reference:"httpd-manual-2.2.3-11.0.1.el5_2.4")) flag++;
if (rpm_check(release:"EL5", reference:"mod_ssl-2.2.3-11.0.1.el5_2.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd / httpd-devel / httpd-manual / httpd-suexec / mod_ssl");
}
