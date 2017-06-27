#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1691. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57019);
  script_version ("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/01/04 16:12:16 $");

  script_cve_id("CVE-2011-1675", "CVE-2011-1677");
  script_osvdb_id(74917, 75268);
  script_xref(name:"RHSA", value:"2011:1691");

  script_name(english:"RHEL 6 : util-linux-ng (RHSA-2011:1691)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated util-linux-ng packages that fix multiple security issues,
several bugs, and add various enhancements are now available for Red
Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The util-linux-ng packages contain a large variety of low-level system
utilities that are necessary for a Linux operating system to function.

Multiple flaws were found in the way the mount and umount commands
performed mtab (mounted file systems table) file updates. A local,
unprivileged user allowed to mount or unmount file systems could use
these flaws to corrupt the mtab file and create a stale lock file,
preventing other users from mounting and unmounting file systems.
(CVE-2011-1675, CVE-2011-1677)

This update also fixes the following bugs :

* Due to a hard-coded limit of 128 devices, an attempt to run the
'blkid -c' command on more than 128 devices caused blkid to terminate
unexpectedly. This update increases the maximum number of devices to
8192 so that blkid no longer crashes in this scenario. (BZ#675999)

* Previously, the 'swapon -a' command did not detect device-mapper
devices that were already in use. This update corrects the swapon
utility to detect such devices as expected. (BZ#679741)

* Prior to this update, the presence of an invalid line in the
/etc/fstab file could cause the umount utility to terminate
unexpectedly with a segmentation fault. This update applies a patch
that corrects this error so that umount now correctly reports invalid
lines and no longer crashes. (BZ#684203)

* Previously, an attempt to use the wipefs utility on a partitioned
device caused the utility to terminate unexpectedly with an error.
This update adapts wipefs to only display a warning message in this
situation. (BZ#696959)

* When providing information on interprocess communication (IPC)
facilities, the ipcs utility could previously display a process owner
as a negative number if the user's UID was too large. This update
adapts the underlying source code to make sure the UID values are now
displayed correctly. (BZ#712158)

* In the installation scriptlets, the uuidd package uses the chkconfig
utility to enable and disable the uuidd service. Previously, this
package did not depend on the chkconfig package, which could lead to
errors during installation if chkconfig was not installed. This update
adds chkconfig to the list of dependencies so that such errors no
longer occur. (BZ#712808)

* The previous version of the /etc/udev/rules.d/60-raw.rules file
contained a statement that both this file and raw devices are
deprecated. This is no longer true and the Red Hat Enterprise Linux
kernel supports this functionality. With this update, the
aforementioned file no longer contains this incorrect statement.
(BZ#716995)

* Previously, an attempt to use the cfdisk utility to read the default
Red Hat Enterprise Linux 6 partition layout failed with an error. This
update corrects this error and the cfdisk utility can now read the
default partition layout as expected. (BZ#723352)

* The previous version of the tailf(1) manual page incorrectly stated
that users can use the '--lines=NUMBER' command line option to limit
the number of displayed lines. However, the tailf utility does not
allow the use of the equals sign (=) between the option and its
argument. This update corrects this error. (BZ#679831)

* The fstab(5) manual page has been updated to clarify that empty
lines in the /etc/fstab configuration file are ignored. (BZ#694648)

As well, this update adds the following enhancements :

* A new fstrim utility has been added to the package. This utility
allows the root user to discard unused blocks on a mounted file
system. (BZ#692119)

* The login utility has been updated to provide support for failed
login attempts that are reported by PAM. (BZ#696731)

* The lsblk utility has been updated to provide additional information
about the topology and status of block devices. (BZ#723638)

* The agetty utility has been updated to pass the hostname to the
login utility. (BZ#726092)

All users of util-linux-ng are advised to upgrade to these updated
packages, which contain backported patches to correct these issues and
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
    value:"http://rhn.redhat.com/errata/RHSA-2011-1691.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libblkid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libblkid-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libuuid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libuuid-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:util-linux-ng");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:util-linux-ng-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:uuidd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2011:1691";
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
  if (rpm_check(release:"RHEL6", reference:"libblkid-2.17.2-12.4.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libblkid-devel-2.17.2-12.4.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libuuid-2.17.2-12.4.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libuuid-devel-2.17.2-12.4.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"util-linux-ng-2.17.2-12.4.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"util-linux-ng-debuginfo-2.17.2-12.4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"uuidd-2.17.2-12.4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"uuidd-2.17.2-12.4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"uuidd-2.17.2-12.4.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libblkid / libblkid-devel / libuuid / libuuid-devel / util-linux-ng / etc");
  }
}
