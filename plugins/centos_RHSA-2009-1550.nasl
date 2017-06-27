#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1550 and 
# CentOS Errata and Security Advisory 2009:1550 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(67070);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/11/17 20:59:10 $");

  script_cve_id("CVE-2008-5029", "CVE-2008-5300", "CVE-2009-1337", "CVE-2009-1385", "CVE-2009-1895", "CVE-2009-2691", "CVE-2009-2695", "CVE-2009-2848", "CVE-2009-2849", "CVE-2009-2910", "CVE-2009-3002", "CVE-2009-3228", "CVE-2009-3547", "CVE-2009-3612", "CVE-2009-3613", "CVE-2009-3620", "CVE-2009-3621");
  script_bugtraq_id(32154, 34405, 35185, 35647, 35930, 36176, 36901);
  script_osvdb_id(49946, 50272, 53629, 54892, 55807, 56981, 57209, 57264, 57428, 57757, 57821, 59068, 59070, 59082, 59210, 59211, 59222, 59654);
  script_xref(name:"RHSA", value:"2009:1550");

  script_name(english:"CentOS 3 : kernel (CESA-2009:1550)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix several security issues and multiple
bugs are now available for Red Hat Enterprise Linux 3.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security fixes :

* when fput() was called to close a socket, the __scm_destroy()
function in the Linux kernel could make indirect recursive calls to
itself. This could, potentially, lead to a denial of service issue.
(CVE-2008-5029, Important)

* the sendmsg() function in the Linux kernel did not block during UNIX
socket garbage collection. This could, potentially, lead to a local
denial of service. (CVE-2008-5300, Important)

* the exit_notify() function in the Linux kernel did not properly
reset the exit signal if a process executed a set user ID (setuid)
application before exiting. This could allow a local, unprivileged
user to elevate their privileges. (CVE-2009-1337, Important)

* a flaw was found in the Intel PRO/1000 network driver in the Linux
kernel. Frames with sizes near the MTU of an interface may be split
across multiple hardware receive descriptors. Receipt of such a frame
could leak through a validation check, leading to a corruption of the
length check. A remote attacker could use this flaw to send a
specially crafted packet that would cause a denial of service or code
execution. (CVE-2009-1385, Important)

* the ADDR_COMPAT_LAYOUT and MMAP_PAGE_ZERO flags were not cleared
when a setuid or setgid program was executed. A local, unprivileged
user could use this flaw to bypass the mmap_min_addr protection
mechanism and perform a NULL pointer dereference attack, or bypass the
Address Space Layout Randomization (ASLR) security feature.
(CVE-2009-1895, Important)

* it was discovered that, when executing a new process, the
clear_child_tid pointer in the Linux kernel is not cleared. If this
pointer points to a writable portion of the memory of the new program,
the kernel could corrupt four bytes of memory, possibly leading to a
local denial of service or privilege escalation. (CVE-2009-2848,
Important)

* missing initialization flaws were found in getname() implementations
in the IrDA sockets, AppleTalk DDP protocol, NET/ROM protocol, and
ROSE protocol implementations in the Linux kernel. Certain data
structures in these getname() implementations were not initialized
properly before being copied to user-space. These flaws could lead to
an information leak. (CVE-2009-3002, Important)

* a NULL pointer dereference flaw was found in each of the following
functions in the Linux kernel: pipe_read_open(), pipe_write_open(),
and pipe_rdwr_open(). When the mutex lock is not held, the i_pipe
pointer could be released by other processes before it is used to
update the pipe's reader and writer counters. This could lead to a
local denial of service or privilege escalation. (CVE-2009-3547,
Important)

Bug fixes :

* this update adds the mmap_min_addr tunable and restriction checks to
help prevent unprivileged users from creating new memory mappings
below the minimum address. This can help prevent the exploitation of
NULL pointer dereference bugs. Note that mmap_min_addr is set to zero
(disabled) by default for backwards compatibility. (BZ#512642)

* a bridge reference count problem in IPv6 has been fixed. (BZ#457010)

* enforce null-termination of user-supplied arguments to setsockopt().
(BZ#505514)

* the gcc flag '-fno-delete-null-pointer-checks' was added to the
kernel build options. This prevents gcc from optimizing out NULL
pointer checks after the first use of a pointer. NULL pointer bugs are
often exploited by attackers. Keeping these checks is a safety
measure. (BZ#511185)

* a check has been added to the IPv4 code to make sure that rt is not
NULL, to help prevent future bugs in functions that call
ip_append_data() from being exploitable. (BZ#520300)

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. The system must be
rebooted for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-November/016300.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ff34b970"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-November/016301.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5e578c37"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(16, 20, 119, 189, 200, 264, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-BOOT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-hugemem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-hugemem-unsupported");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-smp-unsupported");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-unsupported");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/03");
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
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-2.4.21-63.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"kernel-2.4.21-63.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-BOOT-2.4.21-63.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-doc-2.4.21-63.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"kernel-doc-2.4.21-63.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-hugemem-2.4.21-63.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-hugemem-unsupported-2.4.21-63.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-smp-2.4.21-63.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"kernel-smp-2.4.21-63.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-smp-unsupported-2.4.21-63.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"kernel-smp-unsupported-2.4.21-63.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-source-2.4.21-63.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"kernel-source-2.4.21-63.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-unsupported-2.4.21-63.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"kernel-unsupported-2.4.21-63.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
