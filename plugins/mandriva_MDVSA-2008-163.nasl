#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2008:163. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(37212);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/11/28 21:39:22 $");

  script_cve_id(
    "CVE-2008-1679",
    "CVE-2008-2315",
    "CVE-2008-2316",
    "CVE-2008-3142",
    "CVE-2008-3143",
    "CVE-2008-3144"
  );
  script_bugtraq_id(
    28715,
    30491
  );
  script_osvdb_id(
    44463,
    47478,
    47479,
    47480,
    47481,
    50092,
    50093,
    50094,
    50095,
    50096
  );
  script_xref(name:"MDVSA", value:"2008:163");

  script_name(english:"Mandriva Linux Security Advisory : python (MDVSA-2008:163)");
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
"Multiple integer overflows in the imageop module in Python prior to
2.5.3 allowed context-dependent attackers to cause a denial of service
(crash) or possibly execute arbitrary code via crafted images that
trigger heap-based buffer overflows (CVE-2008-1679). This was due to
an incomplete fix for CVE-2007-4965.

David Remahl of Apple Product Security reported several integer
overflows in a number of core modules (CVE-2008-2315). He also
reported an integer overflow in the hashlib module on Python 2.5 that
lead to unreliable cryptographic digest results (CVE-2008-2316).

Justin Ferguson reported multiple buffer overflows in unicode string
processing that affected 32bit systems (CVE-2008-3142).

Multiple integer overflows were reported by the Google Security Team
that had been fixed in Python 2.5.2 (CVE-2008-3143).

Justin Ferguson reported a number of integer overflows and underflows
in the PyOS_vsnprintf() function, as well as an off-by-one error when
passing zero-length strings, that led to memory corruption
(CVE-2008-3144).

The updated packages have been patched to correct these issues. As
well, Python packages on Mandriva Linux 2007.1 and 2008.0 have been
updated to version 2.5.2. Due to slight packaging changes on Mandriva
Linux 2007.1, a new package is available (tkinter-apps) that contains
binary files (such as /usr/bin/idle) that were previously in the
tkinter package."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64python2.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64python2.5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpython2.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpython2.5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tkinter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tkinter-apps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007.1");
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
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64python2.5-2.5.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64python2.5-devel-2.5.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libpython2.5-2.5.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libpython2.5-devel-2.5.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"python-2.5.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"python-base-2.5.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"python-docs-2.5.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"tkinter-2.5.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"tkinter-apps-2.5.2-2.2mdv2007.1", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64python2.5-2.5.2-2.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64python2.5-devel-2.5.2-2.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libpython2.5-2.5.2-2.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libpython2.5-devel-2.5.2-2.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"python-2.5.2-2.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"python-base-2.5.2-2.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"python-docs-2.5.2-2.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"tkinter-2.5.2-2.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"tkinter-apps-2.5.2-2.2mdv2008.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2008.1", cpu:"x86_64", reference:"lib64python2.5-2.5.2-2.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"x86_64", reference:"lib64python2.5-devel-2.5.2-2.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"libpython2.5-2.5.2-2.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"libpython2.5-devel-2.5.2-2.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"python-2.5.2-2.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"python-base-2.5.2-2.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"python-docs-2.5.2-2.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"tkinter-2.5.2-2.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"tkinter-apps-2.5.2-2.2mdv2008.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
