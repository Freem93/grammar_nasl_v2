#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2006:059. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(21133);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2013/05/31 23:56:38 $");

  script_cve_id("CVE-2005-2709", "CVE-2005-3044", "CVE-2005-3359", "CVE-2006-0457", "CVE-2006-0554", "CVE-2006-0555", "CVE-2006-0557", "CVE-2006-0741", "CVE-2006-0742");
  script_xref(name:"MDKSA", value:"2006:059");

  script_name(english:"Mandrake Linux Security Advisory : kernel (MDKSA-2006:059)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandrake Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A number of vulnerabilities were discovered and corrected in the Linux
2.6 kernel :

sysctl.c in the Linux kernel prior to 2.6.14.1 allows local users to
cause a Denial of Service (kernel oops) and possibly execute code by
opening an interface file in /proc/sys/net/ipv4/conf/, waiting until
the interface is unregistered, then obtaining and modifying function
pointers in memory that was used for the ctl_table (CVE-2005-2709).

Multiple vulnerabilities in versions prior to 2.6.13.2 allow local
users to cause a DoS (oops from null dereference) via fput in a 32bit
ioctl on 64-bit x86 systems or sockfd_put in the 32-bit routing_ioctl
function on 64-bit systems (CVE-2005-3044). Note that this was
previously partially corrected in MDKSA-2005:235.

Prior to 2.6.14, the kernel's atm module allows local users to cause a
DoS (panic) via certain socket calls that produce inconsistent
reference counts for loadable protocol modules (CVE-2005-3359).

A race condition in the (1) add_key, (2) request_key, and (3) keyctl
functions in the 2.6.x kernel allows local users to cause a DoS
(crash) or read sensitive kernel memory by modifying the length of a
string argument between the time that the kernel calculates the length
and when it copies the data into kernel memory (CVE-2006-0457).

Prior to 2.6.15.5, the kernel allows local users to obtain sensitive
information via a crafted XFS ftruncate call, which may return stale
data (CVE-2006-0554).

Prior to 2.6.15.5, the kernel allows local users to cause a DoS (NFS
client panic) via unknown attack vectors related to the use of
O_DIRECT (CVE-2006-0555).

Prior to an including kernel 2.6.16, sys_mbind in mempolicy.c does not
sanity check the maxnod variable before making certain computations,
which has an unknown impact and attack vectors (CVE-2006-0557).

Prior to 2.6.15.5, the kernel allows local users to cause a DoS
('endless recursive fault') via unknown attack vectors related to a
'bad elf entry address' on Intel processors (CVE-2006-0741).

Prior to 2.6.15.6, the die_if_kernel function in the kernel can allow
local users to cause a DoS by causing user faults on Itanium systems
(CVE-2006-00742).

A race in the signal-handling code which allows a process to become
unkillable when the race is triggered was also fixed.

In addition to these security fixes, other fixes have been included
such as :

  - add ich8 support

    - libata locking rewrite

    - libata clear ATA_QCFLAG_ACTIVE flag before calling the
      completion callback

  - support the Acer Aspire 5xxx/3xxx series in the acerhk
    module

    - USB storage: remove info sysfs file as it violates the
      sysfs one value per file rule

  - fix OOPS in sysfs_hash_and_remove_file()

    - pl2303 USB driver fixes; makes pl2303HX chip work
      correctly

    - fix OOPS in IPMI driver which is probably caused when
      trying to use ACPI functions when ACPI was not
      properly initialized

  - fix de_thread() racy BUG_ON()

The provided packages are patched to fix these vulnerabilities. All
users are encouraged to upgrade to these updated kernels.

To update your kernel, please follow the directions located at :

http://www.mandriva.com/en/security/kernelupdate

Please note that users using the LSI Logic 53c1030 dual-channel ultra
320 SCSI card will need to re-create their initrd images manually
prior to rebooting in order to fix a bug that prevents booting. A
future update will correct this problem. To do this, execute :

# rm /boot/initrd-2.6.12-18mdk.img # mkinitrd
/boot/initrd-2.6.12-18mdk.img 2.6.12-18mdk --with-module=mptspi"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-2.6.12.18mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-BOOT-2.6.12.18mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-i586-up-1GB-2.6.12.18mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-i686-up-4GB-2.6.12.18mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-smp-2.6.12.18mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-stripped-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-xbox-2.6.12.18mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-xen0-2.6.12.18mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-xenU-2.6.12.18mdk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/03/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK2006.0", reference:"kernel-2.6.12.18mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"kernel-BOOT-2.6.12.18mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"kernel-i586-up-1GB-2.6.12.18mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"kernel-i686-up-4GB-2.6.12.18mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"kernel-smp-2.6.12.18mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"kernel-source-2.6-2.6.12-18mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"kernel-source-stripped-2.6-2.6.12-18mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"kernel-xbox-2.6.12.18mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"kernel-xen0-2.6.12.18mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"kernel-xenU-2.6.12.18mdk-1-1mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
