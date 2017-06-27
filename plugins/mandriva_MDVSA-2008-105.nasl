#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2008:105. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(37772);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/28 21:39:22 $");

  script_cve_id("CVE-2007-3740", "CVE-2007-3851", "CVE-2007-4133", "CVE-2007-4573", "CVE-2007-4997", "CVE-2007-5093", "CVE-2008-1375", "CVE-2008-1669");
  script_bugtraq_id(25263, 25672, 25774, 26337, 29003, 29076);
  script_xref(name:"MDVSA", value:"2008:105");

  script_name(english:"Mandriva Linux Security Advisory : kernel (MDVSA-2008:105)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandriva Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The CIFS filesystem in the Linux kernel before 2.6.22, when Unix
extension support is enabled, does not honor the umask of a process,
which allows local users to gain privileges. (CVE-2007-3740)

The drm/i915 component in the Linux kernel before 2.6.22.2, when used
with i965G and later chipsets, allows local users with access to an
X11 session and Direct Rendering Manager (DRM) to write to arbitrary
memory locations and gain privileges via a crafted batchbuffer.
(CVE-2007-3851)

The (1) hugetlb_vmtruncate_list and (2) hugetlb_vmtruncate functions
in fs/hugetlbfs/inode.c in the Linux kernel before 2.6.19-rc4 perform
certain prio_tree calculations using HPAGE_SIZE instead of PAGE_SIZE
units, which allows local users to cause a denial of service (panic)
via unspecified vectors. (CVE-2007-4133)

The IA32 system call emulation functionality in Linux kernel 2.4.x and
2.6.x before 2.6.22.7, when running on the x86_64 architecture, does
not zero extend the eax register after the 32bit entry path to ptrace
is used, which might allow local users to gain privileges by
triggering an out-of-bounds access to the system call table using the
%RAX register. This vulnerability is now being fixed in the Xen kernel
too. (CVE-2007-4573)

Integer underflow in the ieee80211_rx function in
net/ieee80211/ieee80211_rx.c in the Linux kernel 2.6.x before 2.6.23
allows remote attackers to cause a denial of service (crash) via a
crafted SKB length value in a runt IEEE 802.11 frame when the
IEEE80211_STYPE_QOS_DATA flag is set, aka an off-by-two error.
(CVE-2007-4997)

The disconnect method in the Philips USB Webcam (pwc) driver in Linux
kernel 2.6.x before 2.6.22.6 relies on user space to close the device,
which allows user-assisted local attackers to cause a denial of
service (USB subsystem hang and CPU consumption in khubd) by not
closing the device after the disconnect is invoked. NOTE: this rarely
crosses privilege boundaries, unless the attacker can convince the
victim to unplug the affected device. (CVE-2007-5093)

A race condition in the directory notification subsystem (dnotify) in
Linux kernel 2.6.x before 2.6.24.6, and 2.6.25 before 2.6.25.1, allows
local users to cause a denial of service (OOPS) and possibly gain
privileges via unspecified vectors. (CVE-2008-1375)

The Linux kernel before 2.6.25.2 does not apply a certain protection
mechanism for fcntl functionality, which allows local users to (1)
execute code in parallel or (2) exploit a race condition to obtain
re-ordered access to the descriptor table. (CVE-2008-1669)

To update your kernel, please follow the directions located at :

http://www.mandriva.com/en/security/kernelupdate"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94, 189, 264, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-2.6.17.18mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-doc-2.6.17.18mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-doc-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-enterprise-2.6.17.18mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-enterprise-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-legacy-2.6.17.18mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-legacy-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-2.6.17.18mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-stripped-2.6.17.18mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-stripped-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-xen0-2.6.17.18mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-xen0-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-xenU-2.6.17.18mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-xenU-latest");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2007.1", reference:"kernel-2.6.17.18mdv-1-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kernel-doc-2.6.17.18mdv-1-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kernel-doc-latest-2.6.17-18mdv", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"kernel-enterprise-2.6.17.18mdv-1-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"kernel-enterprise-latest-2.6.17-18mdv", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kernel-latest-2.6.17-18mdv", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"kernel-legacy-2.6.17.18mdv-1-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"kernel-legacy-latest-2.6.17-18mdv", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kernel-source-2.6.17.18mdv-1-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kernel-source-latest-2.6.17-18mdv", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kernel-source-stripped-2.6.17.18mdv-1-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kernel-source-stripped-latest-2.6.17-18mdv", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kernel-xen0-2.6.17.18mdv-1-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kernel-xen0-latest-2.6.17-18mdv", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kernel-xenU-2.6.17.18mdv-1-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kernel-xenU-latest-2.6.17-18mdv", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
