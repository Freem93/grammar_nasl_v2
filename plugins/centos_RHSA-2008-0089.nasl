#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0089 and 
# CentOS Errata and Security Advisory 2008:0089 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43672);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/17 20:59:08 $");

  script_cve_id("CVE-2007-3104", "CVE-2007-5904", "CVE-2007-6206", "CVE-2007-6416", "CVE-2008-0001");
  script_bugtraq_id(24631, 26438, 26701, 27280);
  script_osvdb_id(40910, 41344);
  script_xref(name:"RHSA", value:"2008:0089");

  script_name(english:"CentOS 5 : kernel (CESA-2008:0089)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix several security issues and several
bugs in the Red Hat Enterprise Linux 5 kernel are now available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

These new kernel packages fix the following security issues :

A flaw was found in the virtual filesystem (VFS). An unprivileged
local user could truncate directories to which they had write
permission; this could render the contents of the directory
inaccessible. (CVE-2008-0001, Important)

A flaw was found in the Xen PAL emulation on Intel 64 platforms. A
guest Hardware-assisted virtual machine (HVM) could read the arbitrary
physical memory of the host system, which could make information
available to unauthorized users. (CVE-2007-6416, Important)

A flaw was found in the way core dump files were created. If a local
user can get a root-owned process to dump a core file into a
directory, which the user has write access to, they could gain read
access to that core file, potentially containing sensitive
information. (CVE-2007-6206, Moderate)

A buffer overflow flaw was found in the CIFS virtual file system. A
remote,authenticated user could issue a request that could lead to a
denial of service. (CVE-2007-5904, Moderate)

A flaw was found in the 'sysfs_readdir' function. A local user could
create a race condition which would cause a denial of service (kernel
oops). (CVE-2007-3104, Moderate)

As well, these updated packages fix the following bugs :

* running the 'strace -f' command caused strace to hang, without
displaying information about child processes.

* unmounting an unresponsive, interruptable NFS mount, for example,
one mounted with the 'intr' option, may have caused a system crash.

* a bug in the s2io.ko driver prevented VLAN devices from being added.
Attempting to add a device to a VLAN, for example, running the
'vconfig add [device-name] [vlan-id]' command caused vconfig to fail.

* tux used an incorrect open flag bit. This caused problems when
building packages in a chroot environment, such as mock, which is used
by the koji build system.

Red Hat Enterprise Linux 5 users are advised to upgrade to these
updated packages, which contain backported patches to resolve these
issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-January/014639.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3a4835bf"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-January/014640.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?700f80e6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(16, 119, 264, 399);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"kernel-2.6.18-53.1.6.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-2.6.18-53.1.6.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-53.1.6.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-2.6.18-53.1.6.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-devel-2.6.18-53.1.6.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-devel-2.6.18-53.1.6.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-doc-2.6.18-53.1.6.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-headers-2.6.18-53.1.6.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-2.6.18-53.1.6.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-devel-2.6.18-53.1.6.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
