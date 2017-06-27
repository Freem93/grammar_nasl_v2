#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0307. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58061);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/01/05 16:04:21 $");

  script_cve_id("CVE-2011-1675", "CVE-2011-1677");
  script_bugtraq_id(50941);
  script_osvdb_id(74917, 75268);
  script_xref(name:"RHSA", value:"2012:0307");

  script_name(english:"RHEL 5 : util-linux (RHSA-2012:0307)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated util-linux package that fixes multiple security issues,
various bugs, and adds two enhancements is now available for Red Hat
Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having low
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The util-linux package contains a large variety of low-level system
utilities that are necessary for a Linux system to function. Among
others, util-linux contains the fdisk configuration tool and the login
program.

Multiple flaws were found in the way the mount and umount commands
performed mtab (mounted file systems table) file updates. A local,
unprivileged user allowed to mount or unmount file systems could use
these flaws to corrupt the mtab file and create a stale lock file,
preventing other users from mounting and unmounting file systems.
(CVE-2011-1675, CVE-2011-1677)

This update also fixes the following bugs :

* When the user logged into a telnet server, the login utility did not
update the utmp database properly if the utility was executed from the
telnetd daemon. This was due to telnetd not creating an appropriate
entry in a utmp file before executing login. With this update, correct
entries are created and the database is updated properly. (BZ#646300)

* Various options were not described on the blockdev(8) manual page.
With this update, the blockdev(8) manual page includes all the
relevant options. (BZ#650937)

* Prior to this update, the build process of the util-linux package
failed in the po directory with the following error message:
'@MKINSTALLDIRS@: No such file or directory'. An upstream patch has
been applied to address this issue, and the util-linux package now
builds successfully. (BZ#677452)

* Previously, the ipcs(1) and ipcrm(1) manual pages mentioned an
invalid option, '-b'. With this update, only valid options are listed
on those manual pages. (BZ#678407)

* Previously, the mount(8) manual page contained incomplete
information about the ext4 and XFS file systems. With this update, the
mount(8) manual page contains the missing information. (BZ#699639)

In addition, this update adds the following enhancements :

* Previously, if DOS mode was enabled on a device, the fdisk utility
could report error messages similar to the following :

Partition 1 has different physical/logical beginnings (non-Linux?):
phys=(0, 1, 1) logical=(0, 2, 7)

This update enables users to switch off DOS compatible mode (by
specifying the '-c' option), and such error messages are no longer
displayed. (BZ#678430)

* This update adds the 'fsfreeze' command which halts access to a file
system on a disk. (BZ#726572)

All users of util-linux are advised to upgrade to this updated
package, which contains backported patches to correct these issues and
add these enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1675.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1677.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-0307.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected util-linux and / or util-linux-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:util-linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:util-linux-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/21");
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
  rhsa = "RHSA-2012:0307";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"util-linux-2.13-0.59.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"util-linux-2.13-0.59.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"util-linux-2.13-0.59.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"util-linux-debuginfo-2.13-0.59.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"util-linux-debuginfo-2.13-0.59.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"util-linux-debuginfo-2.13-0.59.el5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "util-linux / util-linux-debuginfo");
  }
}
