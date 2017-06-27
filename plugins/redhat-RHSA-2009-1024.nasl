#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1024. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38818);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2017/01/03 17:27:01 $");

  script_cve_id("CVE-2009-1336", "CVE-2009-1337");
  script_bugtraq_id(34405);
  script_osvdb_id(53629, 53951);
  script_xref(name:"RHSA", value:"2009:1024");

  script_name(english:"RHEL 4 : kernel (RHSA-2009:1024)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages are now available as part of the ongoing
support and maintenance of Red Hat Enterprise Linux version 4. This is
the eighth regular update.

These updated packages fix two security issues, hundreds of bugs, and
add numerous enhancements. Space precludes a detailed description of
each of these in this advisory. Refer to the Red Hat Enterprise Linux
4.8 Release Notes for information on 22 of the most significant of
these changes. For more detailed information on specific bug fixes or
enhancements, refer to the Bugzilla numbers associated with this
advisory.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fixes :

* the exit_notify() function in the Linux kernel did not properly
reset the exit signal if a process executed a set user ID (setuid)
application before exiting. This could allow a local, unprivileged
user to elevate their privileges. (CVE-2009-1337, Important)

* the Linux kernel implementation of the Network File System (NFS) did
not properly initialize the file name limit in the nfs_server data
structure. This flaw could possibly lead to a denial of service on a
client mounting an NFS share. (CVE-2009-1336, Moderate)

Bug Fixes and Enhancements :

Kernel Feature Support :

* added a new allowable value to '/proc/sys/kernel/wake_balance' to
allow the scheduler to run the thread on any available CPU rather than
scheduling it on the optimal CPU. * added 'max_writeback_pages'
tunable parameter to /proc/sys/vm/ to allow the maximum number of
modified pages kupdate writes to disk, per iteration per run. * added
'swap_token_timeout' tunable parameter to /proc/sys/vm/ to provide a
valid hold time for the swap out protection token. * added diskdump
support to sata_svw driver. * limited physical memory to 64GB for
32-bit kernels running on systems with more than 64GB of physical
memory to prevent boot failures. * improved reliability of autofs. *
added support for 'rdattr_error' in NFSv4 readdir requests. * fixed
various short packet handling issues for NFSv4 readdir and sunrpc. *
fixed several CIFS bugs.

Networking and IPv6 Enablement :

* added router solicitation support. * enforced sg requires tx csum in
ethtool.

Platform Support :

x86, AMD64, Intel 64, IBM System z

* added support for a new Intel chipset. * added initialization vendor
info in boot_cpu_data. * added support for N_Port ID Virtualization
(NPIV) for IBM System z guests using zFCP. * added HDMI support for
some AMD and ATI chipsets. * updated HDA driver in ALSA to latest
upstream as of 2008-07-22. * added support for affected_cpus for
cpufreq. * removed polling timer from i8042. * fixed PM-Timer when
using the ASUS A8V Deluxe motherboard. * backported usbfs_mutex in
usbfs.

64-bit PowerPC :

* updated eHEA driver from version 0078-04 to 0078-08. * updated
logging of checksum errors in the eHEA driver.

Network Driver Updates :

* updated forcedeth driver to latest upstream version 0.61. * fixed
various e1000 issues when using Intel ESB2 hardware. * updated e1000e
driver to upstream version 0.3.3.3-k6. * updated igb to upstream
version 1.2.45-k2. * updated tg3 to upstream version 3.96. * updated
ixgbe to upstream version 1.3.18-k4. * updated bnx2 to upstream
version 1.7.9. * updated bnx2x to upstream version 1.45.23. * fixed
bugs and added enhancements for the NetXen NX2031 and NX3031 products.
* updated Realtek r8169 driver to support newer network chipsets. All
variants of RTL810x/RTL8168(9) are now supported.

Storage Driver Updates :

* fixed various SCSI issues. Also, the SCSI sd driver now calls the
revalidate_disk wrapper. * fixed a dmraid reduced I/O delay bug in
certain configurations. * removed quirk aac_quirk_scsi_32 for some
aacraid controllers. * updated FCP driver on IBM System z systems with
support for point-to-point connections. * updated lpfc to version
8.0.16.46. * updated megaraid_sas to version 4.01-RH1. * updated MPT
Fusion driver to version 3.12.29.00rh. * updated qla2xxx firmware to
4.06.01 for 4GB/s and 8GB/s adapters. * updated qla2xxx driver to
version 8.02.09.00.04.08-d. * fixed sata_nv in libsata to disable ADMA
mode by default.

Miscellaneous Updates :

* upgraded OpenFabrics Alliance Enterprise Distribution (OFED) to
version 1.4. * added driver support and fixes for various Wacom
tablets.

Users should install this update, which resolves these issues and adds
these enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-1336.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-1337.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/4.8/html/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2009-1024.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-hugemem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-hugemem-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-largesmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-largesmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-smp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xenU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xenU-devel");
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
  rhsa = "RHSA-2009:1024";
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
  if (rpm_check(release:"RHEL4", reference:"kernel-2.6.9-89.EL")) flag++;
  if (rpm_check(release:"RHEL4", reference:"kernel-devel-2.6.9-89.EL")) flag++;
  if (rpm_check(release:"RHEL4", reference:"kernel-doc-2.6.9-89.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-hugemem-2.6.9-89.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-hugemem-devel-2.6.9-89.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-89.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-89.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-smp-2.6.9-89.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-smp-2.6.9-89.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-smp-devel-2.6.9-89.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-smp-devel-2.6.9-89.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-xenU-2.6.9-89.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-xenU-2.6.9-89.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-xenU-devel-2.6.9-89.EL")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-xenU-devel-2.6.9-89.EL")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-devel / kernel-doc / kernel-hugemem / etc");
  }
}
