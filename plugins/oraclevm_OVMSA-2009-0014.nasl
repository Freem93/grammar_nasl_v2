#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2009-0014.
#

include("compat.inc");

if (description)
{
  script_id(79460);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/02/14 17:16:23 $");

  script_cve_id("CVE-2009-1072", "CVE-2009-1192", "CVE-2009-1439", "CVE-2009-1630", "CVE-2009-1633", "CVE-2009-1758");
  script_bugtraq_id(34205, 34453, 34612, 34673, 34934, 34957);

  script_name(english:"OracleVM 2.1 : kernel (OVMSA-2009-0014)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

CVE-2009-1192 The (1) agp_generic_alloc_page and (2)
agp_generic_alloc_pages functions in drivers/char/agp/generic.c in the
agp subsystem in the Linux kernel before 2.6.30-rc3 do not zero out
pages that may later be available to a user-space process, which
allows local users to obtain sensitive information by reading these
pages.

CVE-2009-1072 nfsd in the Linux kernel before 2.6.28.9 does not drop
the CAP_MKNOD capability before handling a user request in a thread,
which allows local users to create device nodes, as demonstrated on a
filesystem that has been exported with the root_squash option.

CVE-2009-1758 The hypervisor_callback function in Xen, possibly before
3.4.0, as applied to the Linux kernel 2.6.30-rc4, 2.6.18, and probably
other versions allows guest user applications to cause a denial of
service (kernel oops) of the guest OS by triggering a segmentation
fault in 'certain address ranges.'

CVE-2009-1439 Buffer overflow in fs/cifs/connect.c in CIFS in the
Linux kernel 2.6.29 and earlier allows remote attackers to cause a
denial of service (crash) via a long nativeFileSystem field in a Tree
Connect response to an SMB mount request.

CVE-2009-1633 Multiple buffer overflows in the cifs subsystem in the
Linux kernel before 2.6.29.4 allow remote CIFS servers to cause a
denial of service (memory corruption) and possibly have unspecified
other impact via (1) a malformed Unicode string, related to Unicode
string area alignment in fs/cifs/sess.c  or (2) long Unicode
characters, related to fs/cifs/cifssmb.c and the cifs_readdir function
in fs/cifs/readdir.c.

CVE-2009-1630 The nfs_permission function in fs/nfs/dir.c in the NFS
client implementation in the Linux kernel 2.6.29.3 and earlier, when
atomic_open is available, does not check execute (aka EXEC or
MAY_EXEC) permission bits, which allows local users to bypass
permissions and execute files, as demonstrated by files on an NFSv4
fileserver.

  - [agp] zero pages before sending to userspace (Jiri Olsa)
    [497025 497026] (CVE-2009-1192)

  - [misc] add some long-missing capabilities to CAP_FS_MASK
    (Eric Paris) [499075 497271 499076 497272]
    (CVE-2009-1072)

  - [x86] xen: fix local denial of service (Chris
    Lalancette) [500950 500951] (CVE-2009-1758)

  - [fs] cifs: unicode alignment and buffer sizing problems
    (Jeff Layton) [494279 494280] (CVE-2009-1439)

  - [fs] cifs: buffer overruns when converting strings (Jeff
    Layton) [496576 496577] (CVE-2009-1633)

  - [fs] cifs: fix error handling in parse_DFS_referrals
    (Jeff Layton) [496576 496577] (CVE-2009-1633)

  - [fs] cifs: fix pointer and checks in cifs_follow_symlink
    (Jeff Layton) [496576 496577] (CVE-2009-1633)

  - [nfs] v4: client handling of MAY_EXEC in nfs_permission
    (Peter Staubach) [500301 500302] (CVE-2009-1630)

  - backport cifs support from OEL5U3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2009-July/000027.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(16, 119, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-BOOT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-BOOT-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-ovs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-ovs-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:2.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! ereg(pattern:"^OVS" + "2\.1" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 2.1", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);

flag = 0;
if (rpm_check(release:"OVS2.1", reference:"kernel-BOOT-2.6.18-8.1.15.4.1.el5")) flag++;
if (rpm_check(release:"OVS2.1", reference:"kernel-BOOT-devel-2.6.18-8.1.15.4.1.el5")) flag++;
if (rpm_check(release:"OVS2.1", reference:"kernel-kdump-2.6.18-8.1.15.4.1.el5")) flag++;
if (rpm_check(release:"OVS2.1", reference:"kernel-kdump-devel-2.6.18-8.1.15.4.1.el5")) flag++;
if (rpm_check(release:"OVS2.1", reference:"kernel-ovs-2.6.18-8.1.15.4.1.el5")) flag++;
if (rpm_check(release:"OVS2.1", reference:"kernel-ovs-devel-2.6.18-8.1.15.4.1.el5")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-BOOT / kernel-BOOT-devel / kernel-kdump / kernel-kdump-devel / etc");
}
