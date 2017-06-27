#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1149. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61452);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/01/05 16:04:22 $");

  script_cve_id("CVE-2012-3440");
  script_osvdb_id(84492);
  script_xref(name:"RHSA", value:"2012:1149");

  script_name(english:"RHEL 5 : sudo (RHSA-2012:1149)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated sudo package that fixes one security issue and several bugs
is now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The sudo (superuser do) utility allows system administrators to give
certain users the ability to run commands as root.

An insecure temporary file use flaw was found in the sudo package's
post-uninstall script. A local attacker could possibly use this flaw
to overwrite an arbitrary file via a symbolic link attack, or modify
the contents of the '/etc/nsswitch.conf' file during the upgrade or
removal of the sudo package. (CVE-2012-3440)

This update also fixes the following bugs :

* Previously, sudo escaped non-alphanumeric characters in commands
using 'sudo -s' or 'sudo -' at the wrong place and interfered with the
authorization process. Some valid commands were not permitted. Now,
non-alphanumeric characters escape immediately before the command is
executed and no longer interfere with the authorization process.
(BZ#844418)

* Prior to this update, the sudo utility could, under certain
circumstances, fail to receive the SIGCHLD signal when it was executed
from a process that blocked the SIGCHLD signal. As a consequence, sudo
could become suspended and fail to exit. This update modifies the
signal process mask so that sudo can exit and sends the correct
output. (BZ#844419)

* The sudo update RHSA-2012:0309 introduced a regression that caused
the Security-Enhanced Linux (SELinux) context of the
'/etc/nsswitch.conf' file to change during the installation or upgrade
of the sudo package. This could cause various services confined by
SELinux to no longer be permitted to access the file. In reported
cases, this issue prevented PostgreSQL and Postfix from starting.
(BZ#842759)

* Updating the sudo package resulted in the 'sudoers' line in
'/etc/nsswitch.conf' being removed. This update corrects the bug in
the sudo package's post-uninstall script that caused this issue.
(BZ#844420)

* Prior to this update, a race condition bug existed in sudo. When a
program was executed with sudo, the program could possibly exit
successfully before sudo started waiting for it. In this situation,
the program would be left in a zombie state and sudo would wait for it
endlessly, expecting it to still be running. (BZ#844978)

All users of sudo are advised to upgrade to this updated package,
which contains backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-3440.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://rhn.redhat.com/errata/RHSA-2012-0309.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-1149.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected sudo and / or sudo-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sudo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sudo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2012:1149";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"sudo-1.7.2p1-14.el5_8.2")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"sudo-1.7.2p1-14.el5_8.2")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"sudo-1.7.2p1-14.el5_8.2")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"sudo-debuginfo-1.7.2p1-14.el5_8.2")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"sudo-debuginfo-1.7.2p1-14.el5_8.2")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"sudo-debuginfo-1.7.2p1-14.el5_8.2")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sudo / sudo-debuginfo");
  }
}
