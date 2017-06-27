#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:782. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20048);
  script_version ("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/12/28 18:06:54 $");

  script_cve_id("CVE-2001-1494", "CVE-2005-2876");
  script_bugtraq_id(14816);
  script_osvdb_id(19369, 19934);
  script_xref(name:"RHSA", value:"2005:782");

  script_name(english:"RHEL 2.1 / 3 / 4 : util-linux and mount (RHSA-2005:782)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated util-linux and mount packages that fix two security issues are
now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The util-linux package contains a large variety of low-level system
utilities that are necessary for a Linux system to function.

The mount package contains the mount, umount, swapon and swapoff
programs.

A bug was found in the way the umount command is executed by normal
users. It may be possible for a user to gain elevated privileges if
the user is able to execute the 'umount -r' command on a mounted file
system. The file system will be re-mounted only with the 'readonly'
flag set, clearing flags such as 'nosuid' and 'noexec'. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2005-2876 to this issue.

This update also fixes a hardlink bug in the script command for Red
Hat Enterprise Linux 2.1. If a local user places a hardlinked file
named 'typescript' in a directory they have write access to, the file
will be overwritten if the user running script has write permissions
to the destination file. The Common Vulnerabilities and Exposures
project (cve.mitre.org) has assigned the name CVE-2001-1494 to this
issue.

All users of util-linux and mount should upgrade to these updated
packages, which contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2001-1494.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-2876.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2005-782.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected losetup, mount and / or util-linux packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:losetup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:util-linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/19");
  script_set_attribute(attribute:"vuln_publication_date", value:"2001/12/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(2\.1|3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 2.1 / 3.x / 4.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2005:782";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"losetup-2.11g-9")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mount-2.11g-9")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"util-linux-2.11f-20.8")) flag++;

  if (rpm_check(release:"RHEL3", reference:"losetup-2.11y-31.11")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mount-2.11y-31.11")) flag++;
  if (rpm_check(release:"RHEL3", reference:"util-linux-2.11y-31.11")) flag++;

  if (rpm_check(release:"RHEL4", reference:"util-linux-2.12a-16.EL4.12")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "losetup / mount / util-linux");
  }
}
