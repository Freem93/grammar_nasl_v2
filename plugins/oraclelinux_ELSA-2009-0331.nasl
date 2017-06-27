#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2009:0331 and 
# Oracle Linux Security Advisory ELSA-2009-0331 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(67814);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/07 20:57:50 $");

  script_cve_id("CVE-2008-5700", "CVE-2009-0031", "CVE-2009-0065", "CVE-2009-0322");
  script_bugtraq_id(33113);
  script_osvdb_id(51000, 51253, 51501, 51653);
  script_xref(name:"RHSA", value:"2009:0331");

  script_name(english:"Oracle Linux 4 : kernel (ELSA-2009-0331)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2009:0331 :

Updated kernel packages that resolve several security issues and fix
various bugs are now available for Red Hat Enterprise Linux 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update addresses the following security issues :

* a buffer overflow was found in the Linux kernel Partial Reliable
Stream Control Transmission Protocol (PR-SCTP) implementation. This
could, potentially, lead to a denial of service if a Forward-TSN chunk
is received with a large stream ID. (CVE-2009-0065, Important)

* a memory leak was found in keyctl handling. A local, unprivileged
user could use this flaw to deplete kernel memory, eventually leading
to a denial of service. (CVE-2009-0031, Important)

* a deficiency was found in the Remote BIOS Update (RBU) driver for
Dell systems. This could allow a local, unprivileged user to cause a
denial of service by reading zero bytes from the image_type or
packet_size file in '/sys/devices/platform/dell_rbu/'. (CVE-2009-0322,
Important)

* a deficiency was found in the libATA implementation. This could,
potentially, lead to a denial of service. Note: by default, '/dev/sg*'
devices are accessible only to the root user. (CVE-2008-5700, Low)

This update also fixes the following bugs :

* when the hypervisor changed a page table entry (pte) mapping from
read-only to writable via a make_writable hypercall, accessing the
changed page immediately following the change caused a spurious page
fault. When trying to install a para-virtualized Red Hat Enterprise
Linux 4 guest on a Red Hat Enterprise Linux 5.3 dom0 host, this fault
crashed the installer with a kernel backtrace. With this update, the
'spurious' page fault is handled properly. (BZ#483748)

* net_rx_action could detect its cpu poll_list as non-empty, but have
that same list reduced to empty by the poll_napi path. This resulted
in garbage data being returned when net_rx_action calls list_entry,
which subsequently resulted in several possible crash conditions. The
race condition in the network code which caused this has been fixed.
(BZ#475970, BZ#479681 & BZ#480741)

* a misplaced memory barrier at unlock_buffer() could lead to a
concurrent h_refcounter update which produced a reference counter leak
and, later, a double free in ext3_xattr_release_block(). Consequent to
the double free, ext3 reported an error

ext3_free_blocks_sb: bit already cleared for block [block number]

and mounted itself as read-only. With this update, the memory barrier
is now placed before the buffer head lock bit, forcing the write order
and preventing the double free. (BZ#476533)

* when the iptables module was unloaded, it was assumed the correct
entry for removal had been found if 'wrapper->ops->pf' matched the
value passed in by 'reg->pf'. If several ops ranges were registered
against the same protocol family, however, (which was likely if you
had both ip_conntrack and ip_contrack_* loaded) this assumption could
lead to NULL list pointers and cause a kernel panic. With this update,
'wrapper->ops' is matched to pointer values 'reg', which ensures the
correct entry is removed and results in no NULL list pointers.
(BZ#477147)

* when the pidmap page (used for tracking process ids, pids)
incremented to an even page (ie the second, fourth, sixth, etc. pidmap
page), the alloc_pidmap() routine skipped the page. This resulted in
'holes' in the allocated pids. For example, after pid 32767, you would
expect 32768 to be allocated. If the page skipping behavior presented,
however, the pid allocated after 32767 was 65536. With this update,
alloc_pidmap() no longer skips alternate pidmap pages and allocated
pid holes no longer occur. This fix also corrects an error which
allowed pid_max to be set higher than the pid_max limit has been
corrected. (BZ#479182)

All Red Hat Enterprise Linux 4 users should upgrade to these updated
packages, which contain backported patches to resolve these issues.
The system must be rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-March/000912.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-hugemem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-hugemem-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-largesmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-largesmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-smp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-xenU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-xenU-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 4", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_exists(release:"EL4", rpm:"kernel-2.6.9") && rpm_check(release:"EL4", reference:"kernel-2.6.9-78.0.17.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-devel-2.6.9") && rpm_check(release:"EL4", reference:"kernel-devel-2.6.9-78.0.17.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-doc-2.6.9") && rpm_check(release:"EL4", reference:"kernel-doc-2.6.9-78.0.17.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-hugemem-2.6.9") && rpm_check(release:"EL4", cpu:"i386", reference:"kernel-hugemem-2.6.9-78.0.17.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-hugemem-devel-2.6.9") && rpm_check(release:"EL4", cpu:"i386", reference:"kernel-hugemem-devel-2.6.9-78.0.17.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-largesmp-2.6.9") && rpm_check(release:"EL4", cpu:"ia64", reference:"kernel-largesmp-2.6.9-78.0.17.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-largesmp-2.6.9") && rpm_check(release:"EL4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-78.0.17.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-largesmp-devel-2.6.9") && rpm_check(release:"EL4", cpu:"ia64", reference:"kernel-largesmp-devel-2.6.9-78.0.17.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-largesmp-devel-2.6.9") && rpm_check(release:"EL4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-78.0.17.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-smp-2.6.9") && rpm_check(release:"EL4", cpu:"i386", reference:"kernel-smp-2.6.9-78.0.17.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-smp-2.6.9") && rpm_check(release:"EL4", cpu:"x86_64", reference:"kernel-smp-2.6.9-78.0.17.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-smp-devel-2.6.9") && rpm_check(release:"EL4", cpu:"i386", reference:"kernel-smp-devel-2.6.9-78.0.17.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-smp-devel-2.6.9") && rpm_check(release:"EL4", cpu:"x86_64", reference:"kernel-smp-devel-2.6.9-78.0.17.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-xenU-2.6.9") && rpm_check(release:"EL4", cpu:"i386", reference:"kernel-xenU-2.6.9-78.0.17.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-xenU-2.6.9") && rpm_check(release:"EL4", cpu:"x86_64", reference:"kernel-xenU-2.6.9-78.0.17.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-xenU-devel-2.6.9") && rpm_check(release:"EL4", cpu:"i386", reference:"kernel-xenU-devel-2.6.9-78.0.17.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-xenU-devel-2.6.9") && rpm_check(release:"EL4", cpu:"x86_64", reference:"kernel-xenU-devel-2.6.9-78.0.17.0.1.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "affected kernel");
}
