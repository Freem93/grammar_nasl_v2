#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2007:080. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(24946);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2013/06/01 00:01:19 $");

  script_cve_id("CVE-2007-1003", "CVE-2007-1351", "CVE-2007-1352", "CVE-2007-1667");
  script_xref(name:"MDKSA", value:"2007:080-1");

  script_name(english:"Mandrake Linux Security Advisory : tightvnc (MDKSA-2007:080-1)");
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
"Local exploitation of a memory corruption vulnerability in the X.Org
and XFree86 X server could allow an attacker to execute arbitrary code
with privileges of the X server, typically root.

The vulnerability exists in the ProcXCMiscGetXIDList() function in the
XC-MISC extension. This request is used to determine what resource IDs
are available for use. This function contains two vulnerabilities,
both result in memory corruption of either the stack or heap. The
ALLOCATE_LOCAL() macro used by this function allocates memory on the
stack using alloca() on systems where alloca() is present, or using
the heap otherwise. The handler function takes a user provided value,
multiplies it, and then passes it to the above macro. This results in
both an integer overflow vulnerability, and an alloca() stack pointer
shifting vulnerability. Both can be exploited to execute arbitrary
code. (CVE-2007-1003)

iDefense reported two integer overflows in the way X.org handled
various font files. A malicious local user could exploit these issues
to potentially execute arbitrary code with the privileges of the X.org
server. (CVE-2007-1351, CVE-2007-1352)

TightVNC uses some of the same code base as Xorg, and has the same
vulnerable code.

Updated packages are patched to address these issues.

Update :

Packages for Mandriva Linux 2007.1 are now available."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected tightvnc, tightvnc-doc and / or tightvnc-server
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tightvnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tightvnc-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tightvnc-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/04/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2007.1", reference:"tightvnc-1.2.9-16.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"tightvnc-doc-1.2.9-16.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"tightvnc-server-1.2.9-16.1mdv2007.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
