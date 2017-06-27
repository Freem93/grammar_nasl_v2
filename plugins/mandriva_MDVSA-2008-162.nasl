#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2008:162. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(37509);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/28 21:39:22 $");

  script_cve_id("CVE-2007-1320", "CVE-2007-1321", "CVE-2007-1322", "CVE-2007-1366", "CVE-2007-5729", "CVE-2007-5730", "CVE-2007-6227", "CVE-2008-0928", "CVE-2008-1945", "CVE-2008-2004");
  script_bugtraq_id(23731);
  script_xref(name:"MDVSA", value:"2008:162");

  script_name(english:"Mandriva Linux Security Advisory : qemu (MDVSA-2008:162)");
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
"Multiple vulnerabilities have been found in Qemu.

Multiple heap-based buffer overflows in the cirrus_invalidate_region
function in the Cirrus VGA extension in QEMU 0.8.2, as used in Xen and
possibly other products, might allow local users to execute arbitrary
code via unspecified vectors related to attempting to mark
non-existent regions as dirty, aka the bitblt heap overflow.
(CVE-2007-1320)

Integer signedness error in the NE2000 emulator in QEMU 0.8.2, as used
in Xen and possibly other products, allows local users to trigger a
heap-based buffer overflow via certain register values that bypass
sanity checks, aka QEMU NE2000 receive integer signedness error.
(CVE-2007-1321)

QEMU 0.8.2 allows local users to halt a virtual machine by executing
the icebp instruction. (CVE-2007-1322)

QEMU 0.8.2 allows local users to crash a virtual machine via the
divisor operand to the aam instruction, as demonstrated by aam 0x0,
which triggers a divide-by-zero error. (CVE-2007-1366)

The NE2000 emulator in QEMU 0.8.2 allows local users to execute
arbitrary code by writing Ethernet frames with a size larger than the
MTU to the EN0_TCNT register, which triggers a heap-based buffer
overflow in the slirp library, aka NE2000 mtu heap overflow.
(CVE-2007-5729)

Heap-based buffer overflow in QEMU 0.8.2, as used in Xen and possibly
other products, allows local users to execute arbitrary code via
crafted data in the net socket listen option, aka QEMU net socket heap
overflow. (CVE-2007-5730)

QEMU 0.9.0 allows local users of a Windows XP SP2 guest operating
system to overwrite the TranslationBlock (code_gen_buffer) buffer, and
probably have unspecified other impacts related to an overflow, via
certain Windows executable programs, as demonstrated by qemu-dos.com.
(CVE-2007-6227)

Qemu 0.9.1 and earlier does not perform range checks for block device
read or write requests, which allows guest host users with root
privileges to access arbitrary memory and escape the virtual machine.
(CVE-2008-0928)

Changing removable media in QEMU could trigger a bug similar to
CVE-2008-2004, which would allow local guest users to read arbitrary
files on the host by modifying the header of the image to identify a
different format. (CVE-2008-1945) See the diskformat: parameter to the
-usbdevice option.

The drive_init function in QEMU 0.9.1 determines the format of a raw
disk image based on the header, which allows local guest users to read
arbitrary files on the host by modifying the header to identify a
different format, which is used when the guest is restarted.
(CVE-2008-2004) See the -format option.

The updated packages have been patched to fix these issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dkms-kqemu, qemu and / or qemu-img packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 189, 200, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dkms-kqemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qemu-img");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/07");
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
if (rpm_check(release:"MDK2008.0", reference:"dkms-kqemu-1.3.0-0.pre11.13.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"qemu-0.9.0-16.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"qemu-img-0.9.0-16.2mdv2008.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2008.1", reference:"dkms-kqemu-1.3.0-0.pre11.15.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"qemu-0.9.0-18.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"qemu-img-0.9.0-18.2mdv2008.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
