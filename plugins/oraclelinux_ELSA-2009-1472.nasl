#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2009:1472 and 
# Oracle Linux Security Advisory ELSA-2009-1472 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67935);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 16:49:12 $");

  script_cve_id("CVE-2009-3525");
  script_bugtraq_id(36523);
  script_osvdb_id(58621);
  script_xref(name:"RHSA", value:"2009:1472");

  script_name(english:"Oracle Linux 5 : xen (ELSA-2009-1472)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2009:1472 :

Updated xen packages that fix a security issue and multiple bugs are
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
    value:"https://oss.oracle.com/pipermail/el-errata/2009-October/001180.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected xen packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xen-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"xen-3.0.3-94.el5_4.1")) flag++;
if (rpm_check(release:"EL5", reference:"xen-devel-3.0.3-94.el5_4.1")) flag++;
if (rpm_check(release:"EL5", reference:"xen-libs-3.0.3-94.el5_4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen / xen-devel / xen-libs");
}
