#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2006:197. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(24582);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/03/19 14:49:26 $");

  script_cve_id("CVE-2006-4572", "CVE-2006-4997");
  script_bugtraq_id(20363);
  script_xref(name:"MDKSA", value:"2006:197");

  script_name(english:"Mandrake Linux Security Advisory : kernel (MDKSA-2006:197)");
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
"Some vulnerabilities were discovered and corrected in the Linux 2.6
kernel :

Bugs in the netfilter for IPv6 code, as reported by Mark Dowd, were
fixed (CVE-2006-4572).

The ATM subsystem of the Linux kernel could allow a remote attacker to
cause a Denial of Service (panic) via unknown vectors that cause the
ATM subsystem to access the memory of socket buffers after they are
freed (CVE-2006-4997).

The provided packages are patched to fix these vulnerabilities. All
users are encouraged to upgrade to these updated kernels immediately
and reboot to effect the fixes.

In addition to these security fixes, other fixes have been included
such as :

  - updated to 2.6.17.14 - fix wrong error handling in
    pccard_store_cis - add NX mask for PTE entry on x86_64 -
    fix snd-hda-intel OOPS - backported support
    r8169-related (r8168/r8169SC) network chipsets -
    explicitly initialize some members of the drm_driver
    structure, otherwise NULL init will have bad side
    effects (mach64) - support for building a nosrc.rpm
    package - fixed unplug/eject on pcmcia cards with r8169
    chipsets - fix libata resource conflicts - fix xenU
    crash and re-enable domU boot logs - fix refcount error
    triggered by software using /proc/[pid]/auxv

To update your kernel, please follow the directions located at :

http://www.mandriva.com/en/security/kernelupdate"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-2.6.17.6mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-enterprise-2.6.17.6mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-legacy-2.6.17.6mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-2.6.17.6mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-stripped-2.6.17.6mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-xen0-2.6.17.6mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-xenU-2.6.17.6mdv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2007.0", reference:"kernel-2.6.17.6mdv-1-1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"kernel-enterprise-2.6.17.6mdv-1-1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"kernel-legacy-2.6.17.6mdv-1-1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"kernel-source-2.6.17.6mdv-1-1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"kernel-source-stripped-2.6.17.6mdv-1-1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"kernel-xen0-2.6.17.6mdv-1-1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"kernel-xenU-2.6.17.6mdv-1-1mdv2007.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
