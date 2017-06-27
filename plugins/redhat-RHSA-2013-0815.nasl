#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0815. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66403);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2017/01/05 16:29:43 $");

  script_cve_id("CVE-2012-3499", "CVE-2012-4558", "CVE-2013-1862");
  script_bugtraq_id(58165);
  script_osvdb_id(90556, 90557, 93366);
  script_xref(name:"RHSA", value:"2013:0815");

  script_name(english:"RHEL 5 / 6 : httpd (RHSA-2013:0815)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated httpd packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The Apache HTTP Server is a popular web server.

Cross-site scripting (XSS) flaws were found in the mod_proxy_balancer
module's manager web interface. If a remote attacker could trick a
user, who was logged into the manager web interface, into visiting a
specially crafted URL, it would lead to arbitrary web script execution
in the context of the user's manager interface session.
(CVE-2012-4558)

It was found that mod_rewrite did not filter terminal escape sequences
from its log file. If mod_rewrite was configured with the RewriteLog
directive, a remote attacker could use specially crafted HTTP requests
to inject terminal escape sequences into the mod_rewrite log file. If
a victim viewed the log file with a terminal emulator, it could result
in arbitrary command execution with the privileges of that user.
(CVE-2013-1862)

Cross-site scripting (XSS) flaws were found in the mod_info,
mod_status, mod_imagemap, mod_ldap, and mod_proxy_ftp modules. An
attacker could possibly use these flaws to perform XSS attacks if they
were able to make the victim's browser generate an HTTP request with a
specially crafted Host header. (CVE-2012-3499)

All httpd users should upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the updated packages, the httpd daemon will be restarted
automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-3499.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-4558.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1862.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0815.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:UR");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2013:0815";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"httpd-2.2.3-78.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"httpd-2.2.3-78.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"httpd-2.2.3-78.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", reference:"httpd-debuginfo-2.2.3-78.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", reference:"httpd-devel-2.2.3-78.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"httpd-manual-2.2.3-78.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"httpd-manual-2.2.3-78.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"httpd-manual-2.2.3-78.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"mod_ssl-2.2.3-78.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"mod_ssl-2.2.3-78.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"mod_ssl-2.2.3-78.el5_9")) flag++;


  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"httpd-2.2.15-28.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"httpd-2.2.15-28.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"httpd-2.2.15-28.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"httpd-debuginfo-2.2.15-28.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"httpd-devel-2.2.15-28.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"httpd-manual-2.2.15-28.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"httpd-tools-2.2.15-28.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"httpd-tools-2.2.15-28.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"httpd-tools-2.2.15-28.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"mod_ssl-2.2.15-28.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"mod_ssl-2.2.15-28.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mod_ssl-2.2.15-28.el6_4")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd / httpd-debuginfo / httpd-devel / httpd-manual / httpd-tools / etc");
  }
}
