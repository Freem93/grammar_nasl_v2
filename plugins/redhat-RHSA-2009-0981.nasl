#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0981. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38817);
  script_version ("$Revision: 1.19 $");
  script_cvs_date("$Date: 2017/01/03 17:27:01 $");

  script_cve_id("CVE-2008-1926");
  script_xref(name:"RHSA", value:"2009:0981");

  script_name(english:"RHEL 4 : util-linux (RHSA-2009:0981)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated util-linux package that fixes one security issue and
several bugs is now available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

The util-linux package contains a collection of basic system
utilities, such as fdisk and mount.

A log injection attack was found in util-linux when logging log in
attempts via the audit subsystem of the Linux kernel. A remote
attacker could use this flaw to modify certain parts of logged events,
possibly hiding their activities on a system. (CVE-2008-1926)

This updated package also fixes the following bugs :

* partitions created by VMware ESX(tm) were not included in the list of
recognized file systems used by fdisk. Consequently, if VMware ESX was
installed, 'fdisk -l' returned 'Unknown' for these partitions. With
this update, information regarding the VMKcore and VMFS partitions has
been added to the file systems list. On systems running VMware ESX,
'fdisk -l' now lists information about these partitions as expected.
(BZ#447264)

* if a username was not set, the login command would fail with a
Segmentation fault. With this update, login lets the audit system
handle NULL usernames (it sends an AUDIT_USER_LOGIN message to the
audit system in the event there is no username set). (BZ#456213)

* the nfs(5) man page listed version 2 as the default. This is
incorrect: unless otherwise specified, the NFS client uses NFS version
3. The man page has been corrected. (BZ#458539)

* in certain situations, backgrounded NFS mounts died shortly after
being backgrounded when the mount command was executed by the initlog
command, which, for example, would occur when running an init script,
such as running the 'service netfs start' command. In these
situations, running the 'ps -ef' command showed backgrounded NFS
mounts disappearing shortly after being backgrounded. In this updated
package, backgrounded mount processes detach from the controlling
terminal, which resolves this issue. (BZ#461488)

* if a new partition's starting cylinder was beyond one terabyte,
fdisk could not create the partition. This has been fixed. (BZ#471372)

* in rare cases 'mount -a' ignored fstab order and tried to re-mount
file systems on mpath devices. With this update, mount honors fstab
order even in the rare cases reported. (BZ#472186)

* the 'mount --move' command moved a file system's mount point as
expected (for example, /proc/mounts showed the changed mount point as
expected) but did not update /etc/mtab properly. With this update, the
'mount --move' command gathers all necessary information about the old
mount point, copies it to the new mount point and then deletes the old
point, ensuring /etc/mtab is updated properly. (BZ#485004)

Util-linux users are advised to upgrade to this updated package, which
addresses this vulnerability and resolves these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-1926.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2009-0981.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected util-linux package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:util-linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/19");
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
if (! ereg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2009:0981";
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
  if (rpm_check(release:"RHEL4", reference:"util-linux-2.12a-24.el4")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "util-linux");
  }
}
