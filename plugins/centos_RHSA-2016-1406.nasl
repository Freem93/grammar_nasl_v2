#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:1406 and 
# CentOS Errata and Security Advisory 2016:1406 respectively.
#

include("compat.inc");

if (description)
{
  script_id(92026);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/11/17 21:12:11 $");

  script_cve_id("CVE-2016-4565");
  script_osvdb_id(138176);
  script_xref(name:"RHSA", value:"2016:1406");

  script_name(english:"CentOS 6 : kernel (CESA-2016:1406)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix one security issue and several bugs
are now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix :

* A flaw was found in the way certain interfaces of the Linux kernel's
Infiniband subsystem used write() as bi-directional ioctl()
replacement, which could lead to insufficient memory security checks
when being invoked using the the splice() system call. A local
unprivileged user on a system with either Infiniband hardware present
or RDMA Userspace Connection Manager Access module explicitly loaded,
could use this flaw to escalate their privileges on the system.
(CVE-2016-4565, Important)

Red Hat would like to thank Jann Horn for reporting this issue.

This update also fixes the following bugs :

* When providing some services and using the Integrated Services
Digital Network (ISDN), the system could terminate unexpectedly due to
the call of the tty_ldisc_flush() function. The provided patch removes
this call and the system no longer hangs in the described scenario.
(BZ#1337443)

* An update to the Red Hat Enterprise Linux 6.8 kernel added calls of
two functions provided by the ipv6.ko kernel module, which added a
dependency on that module. On systems where ipv6.ko was prevented from
being loaded, the nfsd.ko and lockd.ko modules were unable to be
loaded. Consequently, it was not possible to run an NFS server or to
mount NFS file systems as a client. The underlying source code has
been fixed by adding the symbol_get() function, which determines if
nfsd.ko and lock.ko are loaded into memory and calls them through
function pointers, not directly. As a result, the aforementioned
kernel modules are allowed to be loaded even if ipv6.ko is not, and
the NFS mount works as expected. (BZ#1341496)

* After upgrading the kernel, CPU load average increased compared to
the prior kernel version due to the modification of the scheduler. The
provided patch set reverts the calculation algorithm of this load
average to the the previous version thus resulting in relatively lower
values under the same system load. (BZ#1343015)"
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-July/021977.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?764fd81b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"kernel-2.6.32-642.3.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-abi-whitelists-2.6.32-642.3.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-debug-2.6.32-642.3.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-debug-devel-2.6.32-642.3.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-devel-2.6.32-642.3.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-doc-2.6.32-642.3.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-firmware-2.6.32-642.3.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-headers-2.6.32-642.3.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"perf-2.6.32-642.3.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"python-perf-2.6.32-642.3.1.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
