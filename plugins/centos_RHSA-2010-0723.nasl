#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0723 and 
# CentOS Errata and Security Advisory 2010:0723 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(67080);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/05/19 23:43:07 $");

  script_cve_id("CVE-2010-1083", "CVE-2010-2492", "CVE-2010-2798", "CVE-2010-2938", "CVE-2010-2942", "CVE-2010-2943", "CVE-2010-3015");
  script_bugtraq_id(39042, 42124, 42237, 42477, 42527, 42529);
  script_osvdb_id(62387, 67327, 67893, 68303, 68631);
  script_xref(name:"RHSA", value:"2010:0723");

  script_name(english:"CentOS 5 : kernel (CESA-2010:0723)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix multiple security issues and several
bugs are now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues :

* A buffer overflow flaw was found in the ecryptfs_uid_hash() function
in the Linux kernel eCryptfs implementation. On systems that have the
eCryptfs netlink transport (Red Hat Enterprise Linux 5 does) or where
the '/dev/ecryptfs' file has world-writable permissions (which it does
not, by default, on Red Hat Enterprise Linux 5), a local, unprivileged
user could use this flaw to cause a denial of service or possibly
escalate their privileges. (CVE-2010-2492, Important)

* A miscalculation of the size of the free space of the initial
directory entry in a directory leaf block was found in the Linux
kernel Global File System 2 (GFS2) implementation. A local,
unprivileged user with write access to a GFS2-mounted file system
could perform a rename operation on that file system to trigger a NULL
pointer dereference, possibly resulting in a denial of service or
privilege escalation. (CVE-2010-2798, Important)

* A flaw was found in the Xen hypervisor implementation when running a
system that has an Intel CPU without Extended Page Tables (EPT)
support. While attempting to dump information about a crashing
fully-virtualized guest, the flaw could cause the hypervisor to crash
the host as well. A user with permissions to configure a
fully-virtualized guest system could use this flaw to crash the host.
(CVE-2010-2938, Moderate)

* Information leak flaws were found in the Linux kernel's Traffic
Control Unit implementation. A local attacker could use these flaws to
cause the kernel to leak kernel memory to user-space, possibly leading
to the disclosure of sensitive information. (CVE-2010-2942, Moderate)

* A flaw was found in the Linux kernel's XFS file system
implementation. The file handle lookup could return an invalid inode
as valid. If an XFS file system was mounted via NFS (Network File
System), a local attacker could access stale data or overwrite
existing data that reused the inodes. (CVE-2010-2943, Moderate)

* An integer overflow flaw was found in the extent range checking code
in the Linux kernel's ext4 file system implementation. A local,
unprivileged user with write access to an ext4-mounted file system
could trigger this flaw by writing to a file at a very large file
offset, resulting in a local denial of service. (CVE-2010-3015,
Moderate)

* An information leak flaw was found in the Linux kernel's USB
implementation. Certain USB errors could result in an uninitialized
kernel buffer being sent to user-space. An attacker with physical
access to a target system could use this flaw to cause an information
leak. (CVE-2010-1083, Low)

Red Hat would like to thank Andre Osterhues for reporting
CVE-2010-2492; Grant Diffey of CenITex for reporting CVE-2010-2798;
Toshiyuki Okajima for reporting CVE-2010-3015; and Marcus Meissner for
reporting CVE-2010-1083.

This update also fixes several bugs. Documentation for these bug fixes
will be available shortly from the Technical Notes document linked to
in the References.

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. The system must be
rebooted for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-September/017030.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?86ef12a1"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-September/017031.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?77da4a0c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-PAE-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"kernel-2.6.18-194.17.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-2.6.18-194.17.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-194.17.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-2.6.18-194.17.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-devel-2.6.18-194.17.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-devel-2.6.18-194.17.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-doc-2.6.18-194.17.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-headers-2.6.18-194.17.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-2.6.18-194.17.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-devel-2.6.18-194.17.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
