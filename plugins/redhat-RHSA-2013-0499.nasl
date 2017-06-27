#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0499. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64751);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/01/05 16:17:30 $");

  script_cve_id("CVE-2012-0862");
  script_bugtraq_id(53720);
  script_xref(name:"RHSA", value:"2013:0499");

  script_name(english:"RHEL 6 : xinetd (RHSA-2013:0499)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated xinetd package that fixes one security issue and two bugs
is now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The xinetd package provides a secure replacement for inetd, the
Internet services daemon. xinetd provides access control for all
services based on the address of the remote host and/or on time of
access, and can prevent denial-of-access attacks.

When xinetd services are configured with the 'TCPMUX' or 'TCPMUXPLUS'
type, and the tcpmux-server service is enabled, those services are
accessible via port 1. It was found that enabling the tcpmux-server
service (it is disabled by default) allowed every xinetd service,
including those that are not configured with the 'TCPMUX' or
'TCPMUXPLUS' type, to be accessible via port 1. This could allow a
remote attacker to bypass intended firewall restrictions.
(CVE-2012-0862)

Red Hat would like to thank Thomas Swan of FedEx for reporting this
issue.

This update also fixes the following bugs :

* Prior to this update, a file descriptor array in the service.c
source file was not handled as expected. As a consequence, some of the
descriptors remained open when xinetd was under heavy load.
Additionally, the system log was filled with a large number of
messages that took up a lot of disk space over time. This update
modifies the xinetd code to handle the file descriptors correctly and
messages no longer fill the system log. (BZ#790036)

* Prior to this update, services were disabled permanently when their
CPS limit was reached. As a consequence, a failed bind operation could
occur when xinetd attempted to restart the service. This update adds
additional logic that attempts to restart the service. Now, the
service is only disabled if xinetd cannot restart the service after 30
attempts. (BZ#809271)

All users of xinetd are advised to upgrade to this updated package,
which contains backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0862.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0499.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xinetd and / or xinetd-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xinetd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xinetd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/21");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:0499";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"xinetd-2.3.14-38.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"xinetd-2.3.14-38.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"xinetd-2.3.14-38.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"xinetd-debuginfo-2.3.14-38.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"xinetd-debuginfo-2.3.14-38.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"xinetd-debuginfo-2.3.14-38.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xinetd / xinetd-debuginfo");
  }
}
