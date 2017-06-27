#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0159. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20398);
  script_version ("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/12/29 15:35:18 $");

  script_cve_id("CVE-2005-2970", "CVE-2005-3352", "CVE-2005-3357");
  script_bugtraq_id(15834, 16152);
  script_osvdb_id(20462, 21705, 22261);
  script_xref(name:"RHSA", value:"2006:0159");

  script_name(english:"RHEL 3 / 4 : httpd (RHSA-2006:0159)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Apache httpd packages that correct three security issues are
now available for Red Hat Enterprise Linux 3 and 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The Apache HTTP Server is a popular and freely-available Web server.

A memory leak in the worker MPM could allow remote attackers to cause
a denial of service (memory consumption) via aborted connections,
which prevents the memory for the transaction pool from being reused
for other connections. The Common Vulnerabilities and Exposures
project assigned the name CVE-2005-2970 to this issue. This
vulnerability only affects users who are using the non-default worker
MPM.

A flaw in mod_imap when using the Referer directive with image maps
was discovered. With certain site configurations, a remote attacker
could perform a cross-site scripting attack if a victim can be forced
to visit a malicious URL using certain web browsers. (CVE-2005-3352)

A NULL pointer dereference flaw in mod_ssl was discovered affecting
server configurations where an SSL virtual host is configured with
access control and a custom 400 error document. A remote attacker
could send a carefully crafted request to trigger this issue which
would lead to a crash. This crash would only be a denial of service if
using the non-default worker MPM. (CVE-2005-3357)

Users of httpd should update to these erratum packages which contain
backported patches to correct these issues along with some additional
bugs."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-2970.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-3352.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-3357.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2006-0159.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-suexec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/11");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x / 4.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2006:0159";
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
  if (rpm_check(release:"RHEL3", reference:"httpd-2.0.46-56.ent")) flag++;
  if (rpm_check(release:"RHEL3", reference:"httpd-devel-2.0.46-56.ent")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mod_ssl-2.0.46-56.ent")) flag++;

  if (rpm_check(release:"RHEL4", reference:"httpd-2.0.52-22.ent")) flag++;
  if (rpm_check(release:"RHEL4", reference:"httpd-devel-2.0.52-22.ent")) flag++;
  if (rpm_check(release:"RHEL4", reference:"httpd-manual-2.0.52-22.ent")) flag++;
  if (rpm_check(release:"RHEL4", reference:"httpd-suexec-2.0.52-22.ent")) flag++;
  if (rpm_check(release:"RHEL4", reference:"mod_ssl-2.0.52-22.ent")) flag++;

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
