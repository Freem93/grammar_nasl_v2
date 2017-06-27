#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0981 and 
# CentOS Errata and Security Advisory 2009:0981 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(67065);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/05/27 14:13:12 $");

  script_cve_id("CVE-2008-1926");
  script_xref(name:"RHSA", value:"2009:0981");

  script_name(english:"CentOS 4 : util-linux (CESA-2009:0981)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
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
    value:"http://lists.centos.org/pipermail/centos-announce/2009-May/015886.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected util-linux package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:util-linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"util-linux-2.12a-24.c4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
