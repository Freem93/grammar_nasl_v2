#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:121. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(66133);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/11/25 11:41:41 $");

  script_cve_id("CVE-2012-2652", "CVE-2012-3515", "CVE-2012-6075");
  script_bugtraq_id(53725, 55413, 57420);
  script_xref(name:"MDVSA", value:"2013:121");
  script_xref(name:"MGASA", value:"2012-0185");
  script_xref(name:"MGASA", value:"2012-0263");
  script_xref(name:"MGASA", value:"2013-0025");

  script_name(english:"Mandriva Linux Security Advisory : qemu (MDVSA-2013:121)");
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
"Updated qemu packages fix security vulnerability :

A flaw was found in how qemu, in snapshot mode (-snapshot command line
argument), handled the creation and opening of the temporary file used
to store the difference of the virtualized guest's read-only image and
the current state. In snapshot mode, bdrv_open() creates an empty
temporary file without checking for any mkstemp() or close() failures;
it also ignores the possibility of a buffer overrun given an
exceptionally long /tmp. Because qemu re-opens that file after
creation, it is possible to race qemu and insert a symbolic link with
the same expected name as the temporary file, pointing to an
attacker-chosen file. This can be used to either overwrite the
destination file with the privileges of the user running qemu
(typically root), or to point to an attacker-readable file that could
expose data from the guest to the attacker (CVE-2012-2652).

A flaw was found in the way QEMU handled VT100 terminal escape
sequences when emulating certain character devices. A guest user with
privileges to write to a character device that is emulated on the host
using a virtual console back-end could use this flaw to crash the
qemu-kvm process on the host or, possibly, escalate their privileges
on the host (CVE-2012-3515).

It was discovered that the e1000 emulation code in QEMU does not
enforce frame size limits in the same way as the real hardware does.
This could trigger buffer overflows in the guest operating system
driver for that network card, assuming that the host system does not
discard such frames (which it will by default) (CVE-2012-6075)."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected qemu and / or qemu-img packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qemu-img");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"qemu-1.0-8.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"qemu-img-1.0-8.1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
