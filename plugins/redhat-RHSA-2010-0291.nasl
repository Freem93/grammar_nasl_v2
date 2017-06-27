#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0291. The text 
# itself is copyright (C) Red Hat, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(63925);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/05/02 17:31:16 $");

  script_cve_id("CVE-2010-0727");
  script_xref(name:"RHSA", value:"2010:0291");

  script_name(english:"RHEL 5 : gfs-kmod (RHSA-2010:0291)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gfs-kmod packages that fix one security issue, numerous bugs,
and add one enhancement are now available for Red Hat Enterprise Linux
5.5, kernel release 2.6.18-194.el5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The gfs-kmod packages contain modules that provide the ability to
mount and use GFS file systems.

A flaw was found in the gfs_lock() implementation. The GFS locking
code could skip the lock operation for files that have the S_ISGID bit
(set-group-ID on execution) in their mode set. A local, unprivileged
user on a system that has a GFS file system mounted could use this
flaw to cause a kernel panic. (CVE-2010-0727)

These updated gfs-kmod packages are in sync with the latest kernel
(2.6.18-194.el5). The modules in earlier gfs-kmod packages failed to
load because they did not match the running kernel. It was possible to
force-load the modules. With this update, however, users no longer
need to.

These updated gfs-kmod packages also fix the following bugs :

* when SELinux was in permissive mode, a race condition during file
creation could have caused one or more cluster nodes to be fenced and
lock the remaining nodes out of the GFS file system. This race
condition no longer occurs with this update. (BZ#471258)

* when ACLs (Access Control Lists) are enabled on a GFS file system,
if a transaction that has started to do a write request does not have
enough spare blocks for the operation it causes a kernel panic. This
update ensures that there are enough blocks for the write request
before starting the operation. (BZ#513885)

* requesting a 'flock' on a file in GFS in either read-only or
read-write mode would sometimes cause a 'Resource temporarily
unavailable' state error (error 11 for EWOULDBLOCK) to occur. In these
cases, a flock could not be obtained on the file in question. This has
been fixed with this update so that flocks can successfully be
obtained on GFS files without this error occurring. (BZ#515717)

* the GFS withdraw function is a data integrity feature of GFS file
systems in a cluster. If the GFS kernel module detects an
inconsistency in a GFS file system following an I/O operation, the
file system becomes unavailable to the cluster. The GFS withdraw
function is less severe than a kernel panic, which would cause another
node to fence the node. With this update, you can override the GFS
withdraw function by mounting the file system with the '-o
errors=panic' option specified. When this option is specified, any
errors that would normally cause the system to withdraw cause the
system to panic instead. This stops the node's cluster communications,
which causes the node to be fenced. (BZ#517145)

Finally, these updated gfs-kmod packages provide the following
enhancement :

* the GFS kernel modules have been updated to use the new generic
freeze and unfreeze ioctl interface that is also supported by the
following file systems: ext3, ext4, GFS2, JFS and ReiserFS. With this
update, GFS supports freeze/unfreeze through the VFS-level
FIFREEZE/FITHAW ioctl interface. (BZ#487610)

Users are advised to upgrade to these latest gfs-kmod packages,
updated for use with the 2.6.18-194.el5 kernel, which contain
backported patches to correct these issues, fix these bugs, and add
this enhancement."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-0727.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2010-0291.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected kmod-gfs, kmod-gfs-PAE and / or kmod-gfs-xen
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kmod-gfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kmod-gfs-PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kmod-gfs-xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

flag = 0;
if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kmod-gfs-0.1.34-12.el5")) flag++;
if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kmod-gfs-0.1.34-12.el5")) flag++;
if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kmod-gfs-PAE-0.1.34-12.el5")) flag++;
if (rpm_check(release:"RHEL5", cpu:"i686", reference:"kmod-gfs-xen-0.1.34-12.el5")) flag++;
if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kmod-gfs-xen-0.1.34-12.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
