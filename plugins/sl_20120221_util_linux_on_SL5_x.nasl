#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61272);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:57 $");

  script_cve_id("CVE-2011-1675", "CVE-2011-1677");

  script_name(english:"Scientific Linux Security Update : util-linux on SL5.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The util-linux package contains a large variety of low-level system
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

  - When the user logged into a telnet server, the login
    utility did not update the utmp database properly if the
    utility was executed from the telnetd daemon. This was
    due to telnetd not creating an appropriate entry in a
    utmp file before executing login. With this update,
    correct entries are created and the database is updated
    properly.

  - Various options were not described on the blockdev(8)
    manual page. With this update, the blockdev(8) manual
    page includes all the relevant options.

  - Prior to this update, the build process of the
    util-linux package failed in the po directory with the
    following error message: '@MKINSTALLDIRS@: No such file
    or directory'. An upstream patch has been applied to
    address this issue, and the util-linux package now
    builds successfully.

  - Previously, the ipcs(1) and ipcrm(1) manual pages
    mentioned an invalid option, '-b'. With this update,
    only valid options are listed on those manual pages.

  - Previously, the mount(8) manual page contained
    incomplete information about the ext4 and XFS file
    systems. With this update, the mount(8) manual page
    contains the missing information.

In addition, this update adds the following enhancements :

  - Previously, if DOS mode was enabled on a device, the
    fdisk utility could report error messages similar to the
    following :

Partition 1 has different physical/logical beginnings (non-Linux?):
phys=(0, 1, 1) logical=(0, 2, 7)

This update enables users to switch off DOS compatible mode (by
specifying the '-c' option), and such error messages are no longer
displayed.

  - This update adds the 'fsfreeze' command which halts
    access to a file system on a disk.

All users of util-linux are advised to upgrade to this updated
package, which contains backported patches to correct these issues and
add these enhancements."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1203&L=scientific-linux-errata&T=0&P=3164
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a5e12c88"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected util-linux and / or util-linux-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"util-linux-2.13-0.59.el5")) flag++;
if (rpm_check(release:"SL5", reference:"util-linux-debuginfo-2.13-0.59.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
