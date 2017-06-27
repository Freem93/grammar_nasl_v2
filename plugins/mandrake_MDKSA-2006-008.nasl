#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2006:008. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(20474);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/05/31 23:56:37 $");

  script_cve_id("CVE-2005-3191", "CVE-2005-3192", "CVE-2005-3193", "CVE-2005-3624", "CVE-2005-3625", "CVE-2005-3626", "CVE-2005-3627", "CVE-2005-3628");
  script_xref(name:"MDKSA", value:"2006:008");

  script_name(english:"Mandrake Linux Security Advisory : koffice (MDKSA-2006:008)");
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
"Multiple heap-based buffer overflows in the
DCTStream::readProgressiveSOF and DCTStream::readBaselineSOF functions
in the DCT stream parsing code (Stream.cc) in xpdf 3.01 and earlier,
allow user-complicit attackers to cause a denial of service (heap
corruption) and possibly execute arbitrary code via a crafted PDF file
with an out-of-range number of components (numComps), which is used as
an array index. (CVE-2005-3191)

Heap-based buffer overflow in the StreamPredictor function in Xpdf
3.01 allows remote attackers to execute arbitrary code via a PDF file
with an out-of-range numComps (number of components) field.
(CVE-2005-3192)

Heap-based buffer overflow in the JPXStream::readCodestream function
in the JPX stream parsing code (JPXStream.c) for xpdf 3.01 and earlier
allows user-complicit attackers to cause a denial of service (heap
corruption) and possibly execute arbitrary code via a crafted PDF file
with large size values that cause insufficient memory to be allocated.
(CVE-2005-3193)

An additional patch re-addresses memory allocation routines in
goo/gmem.c (Martin Pitt/Canonical, Dirk Mueller/KDE).

In addition, Chris Evans discovered several other vulnerabilities in
the xpdf code base :

Out-of-bounds heap accesses with large or negative parameters to
'FlateDecode' stream. (CVE-2005-3192)

Out-of-bounds heap accesses with large or negative parameters to
'CCITTFaxDecode' stream. (CVE-2005-3624)

Infinite CPU spins in various places when stream ends unexpectedly.
(CVE-2005-3625)

NULL pointer crash in the 'FlateDecode' stream. (CVE-2005-3626)

Overflows of compInfo array in 'DCTDecode' stream. (CVE-2005-3627)

Possible to use index past end of array in 'DCTDecode' stream.
(CVE-2005-3627)

Possible out-of-bounds indexing trouble in 'DCTDecode' stream.
(CVE-2005-3627)

Koffice uses an embedded copy of the xpdf code, with the same
vulnerabilities.

The updated packages have been patched to correct these problems."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:koffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:koffice-karbon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:koffice-kexi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:koffice-kformula");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:koffice-kivio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:koffice-koshell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:koffice-kpresenter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:koffice-krita");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:koffice-kspread");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:koffice-kugar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:koffice-kword");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:koffice-progs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64koffice2-karbon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64koffice2-karbon-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64koffice2-kexi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64koffice2-kexi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64koffice2-kformula");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64koffice2-kformula-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64koffice2-kivio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64koffice2-kivio-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64koffice2-koshell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64koffice2-kpresenter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64koffice2-krita");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64koffice2-krita-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64koffice2-kspread");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64koffice2-kspread-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64koffice2-kugar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64koffice2-kugar-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64koffice2-kword");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64koffice2-kword-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64koffice2-progs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64koffice2-progs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkoffice2-karbon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkoffice2-karbon-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkoffice2-kexi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkoffice2-kexi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkoffice2-kformula");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkoffice2-kformula-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkoffice2-kivio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkoffice2-kivio-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkoffice2-koshell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkoffice2-kpresenter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkoffice2-krita");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkoffice2-krita-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkoffice2-kspread");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkoffice2-kspread-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkoffice2-kugar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkoffice2-kugar-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkoffice2-kword");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkoffice2-kword-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkoffice2-progs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkoffice2-progs-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/01/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/15");
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
if (rpm_check(release:"MDK2006.0", reference:"koffice-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"koffice-karbon-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"koffice-kexi-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"koffice-kformula-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"koffice-kivio-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"koffice-koshell-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"koffice-kpresenter-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"koffice-krita-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"koffice-kspread-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"koffice-kugar-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"koffice-kword-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"koffice-progs-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64koffice2-karbon-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64koffice2-karbon-devel-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64koffice2-kexi-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64koffice2-kexi-devel-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64koffice2-kformula-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64koffice2-kformula-devel-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64koffice2-kivio-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64koffice2-kivio-devel-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64koffice2-koshell-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64koffice2-kpresenter-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64koffice2-krita-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64koffice2-krita-devel-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64koffice2-kspread-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64koffice2-kspread-devel-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64koffice2-kugar-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64koffice2-kugar-devel-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64koffice2-kword-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64koffice2-kword-devel-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64koffice2-progs-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64koffice2-progs-devel-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libkoffice2-karbon-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libkoffice2-karbon-devel-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libkoffice2-kexi-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libkoffice2-kexi-devel-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libkoffice2-kformula-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libkoffice2-kformula-devel-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libkoffice2-kivio-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libkoffice2-kivio-devel-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libkoffice2-koshell-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libkoffice2-kpresenter-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libkoffice2-krita-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libkoffice2-krita-devel-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libkoffice2-kspread-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libkoffice2-kspread-devel-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libkoffice2-kugar-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libkoffice2-kugar-devel-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libkoffice2-kword-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libkoffice2-kword-devel-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libkoffice2-progs-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libkoffice2-progs-devel-1.4.2-11.2.20060mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
