#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1472. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(41963);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2017/01/03 17:27:02 $");

  script_cve_id("CVE-2009-3525");
  script_bugtraq_id(36523);
  script_osvdb_id(58621);
  script_xref(name:"RHSA", value:"2009:1472");

  script_name(english:"RHEL 5 : xen (RHSA-2009:1472)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated xen packages that fix a security issue and multiple bugs are
now available for Red Hat Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Xen is an open source virtualization framework. Virtualization allows
users to run guest operating systems in virtual machines on top of a
host operating system.

The pyGrub boot loader did not honor the 'password' option in the
grub.conf file for para-virtualized guests. Users with access to a
guest's console could use this flaw to bypass intended access
restrictions and boot the guest with arbitrary kernel boot options,
allowing them to get root privileges in the guest's operating system.
With this update, pyGrub correctly honors the 'password' option in
grub.conf for para-virtualized guests. (CVE-2009-3525)

This update also fixes the following bugs :

* rebooting para-virtualized guests sometimes caused those guests to
crash due to a race condition in the xend node control daemon. This
update fixes this race condition so that rebooting guests no longer
potentially causes them to crash and fail to reboot. (BZ#525141)

* due to a race condition in the xend daemon, a guest could disappear
from the list of running guests following a reboot, even though the
guest rebooted successfully and was running. This update fixes this
race condition so that guests always reappear in the guest list
following a reboot. (BZ#525143)

* attempting to use PCI pass-through to para-virtualized guests on
certain kernels failed with a 'Function not implemented' error
message. As a result, users requiring PCI pass-through on
para-virtualized guests were not able to update the xen packages
without also updating the kernel and thus requiring a reboot. These
updated packages enable PCI pass-through for para-virtualized guests
so that users do not need to upgrade the kernel in order to take
advantage of PCI pass-through functionality. (BZ#525149)

All Xen users should upgrade to these updated packages, which contain
backported patches to correct these issues. After installing the
updated packages, the xend service must be restarted for this update
to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-3525.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2009-1472.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xen, xen-devel and / or xen-libs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xen-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/02");
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
  rhsa = "RHSA-2009:1472";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"xen-3.0.3-94.el5_4.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"xen-3.0.3-94.el5_4.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"xen-devel-3.0.3-94.el5_4.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"xen-devel-3.0.3-94.el5_4.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"xen-libs-3.0.3-94.el5_4.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"xen-libs-3.0.3-94.el5_4.1")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen / xen-devel / xen-libs");
  }
}
