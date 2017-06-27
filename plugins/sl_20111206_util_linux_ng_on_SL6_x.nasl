#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(61200);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/05/02 10:37:33 $");

  script_cve_id("CVE-2011-1675", "CVE-2011-1677");

  script_name(english:"Scientific Linux Security Update : util-linux-ng on SL6.x i386/x86_64");
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
"The util-linux-ng packages contain a large variety of low-level system
utilities that are necessary for a Linux operating system to function.

Multiple flaws were found in the way the mount and umount commands
performed mtab (mounted file systems table) file updates. A local,
unprivileged user allowed to mount or unmount file systems could use
these flaws to corrupt the mtab file and create a stale lock file,
preventing other users from mounting and unmounting file systems.
(CVE-2011-1675, CVE-2011-1677)

This update also fixes the following bugs :

  - Due to a hard-coded limit of 128 devices, an attempt to
    run the 'blkid -c' command on more than 128 devices
    caused blkid to terminate unexpectedly. This update
    increases the maximum number of devices to 8192 so that
    blkid no longer crashes in this scenario.

  - Previously, the 'swapon -a' command did not detect
    device-mapper devices that were already in use. This
    update corrects the swapon utility to detect such
    devices as expected.

  - Prior to this update, the presence of an invalid line in
    the /etc/fstab file could cause the umount utility to
    terminate unexpectedly with a segmentation fault. This
    update applies a patch that corrects this error so that
    umount now correctly reports invalid lines and no longer
    crashes.

  - Previously, an attempt to use the wipefs utility on a
    partitioned device caused the utility to terminate
    unexpectedly with an error. This update adapts wipefs to
    only display a warning message in this situation.

  - When providing information on interprocess communication
    (IPC) facilities, the ipcs utility could previously
    display a process owner as a negative number if the
    user's UID was too large. This update adapts the
    underlying source code to make sure the UID values are
    now displayed correctly.

  - In the installation scriptlets, the uuidd package uses
    the chkconfig utility to enable and disable the uuidd
    service. Previously, this package did not depend on the
    chkconfig package, which could lead to errors during
    installation if chkconfig was not installed. This update
    adds chkconfig to the list of dependencies so that such
    errors no longer occur.

  - The previous version of the
    /etc/udev/rules.d/60-raw.rules file contained a
    statement that both this file and raw devices are
    deprecated. This is no longer true and the Scientific
    Linux kernel supports this functionality. With this
    update, the aforementioned file no longer contains this
    incorrect statement.

  - Previously, an attempt to use the cfdisk utility to read
    the default Scientific Linux 6 partition layout failed
    with an error. This update corrects this error and the
    cfdisk utility can now read the default partition layout
    as expected.

  - The previous version of the tailf(1) manual page
    incorrectly stated that users can use the
    '--lines=NUMBER' command line option to limit the number
    of displayed lines. However, the tailf utility does not
    allow the use of the equals sign (=) between the option
    and its argument. This update corrects this error.

  - The fstab(5) manual page has been updated to clarify
    that empty lines in the /etc/fstab configuration file
    are ignored.

As well, this update adds the following enhancements :

  - A new fstrim utility has been added to the package. This
    utility allows the root user to discard unused blocks on
    a mounted file system.

  - The login utility has been updated to provide support
    for failed login attempts that are reported by PAM.

  - The lsblk utility has been updated to provide additional
    information about the topology and status of block
    devices.

  - The agetty utility has been updated to pass the hostname
    to the login utility.

All users of util-linux-ng are advised to upgrade to these updated
packages, which contain backported patches to correct these issues and
add these enhancements."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1112&L=scientific-linux-errata&T=0&P=1321
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a3b6ddfb"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"libblkid-2.17.2-12.4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libblkid-devel-2.17.2-12.4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libuuid-2.17.2-12.4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libuuid-devel-2.17.2-12.4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"util-linux-ng-2.17.2-12.4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"util-linux-ng-debuginfo-2.17.2-12.4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"uuidd-2.17.2-12.4.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
