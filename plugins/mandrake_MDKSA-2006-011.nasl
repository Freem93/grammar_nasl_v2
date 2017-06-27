#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2006:011. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(20477);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2013/05/31 23:56:37 $");

  script_cve_id("CVE-2005-3191", "CVE-2005-3192", "CVE-2005-3193", "CVE-2005-3624", "CVE-2005-3625", "CVE-2005-3626", "CVE-2005-3627", "CVE-2005-3628");
  script_xref(name:"MDKSA", value:"2006:011");

  script_name(english:"Mandrake Linux Security Advisory : tetex (MDKSA-2006:011)");
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

Tetex uses an embedded copy of the xpdf code, with the same
vulnerabilities.

The updated packages have been patched to correct these problems."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:jadetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-afm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-context");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-dvilj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-dvipdfm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-dvips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-latex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-mfwin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-texi2html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-xdvi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xmltex");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:mandrakesoft:mandrake_linux:le2005");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/01/10");
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
if (rpm_check(release:"MDK10.1", reference:"jadetex-3.12-98.4.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"tetex-2.0.2-19.4.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"tetex-afm-2.0.2-19.4.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"tetex-context-2.0.2-19.4.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"tetex-devel-2.0.2-19.4.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"tetex-doc-2.0.2-19.4.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"tetex-dvilj-2.0.2-19.4.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"tetex-dvipdfm-2.0.2-19.4.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"tetex-dvips-2.0.2-19.4.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"tetex-latex-2.0.2-19.4.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"tetex-mfwin-2.0.2-19.4.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"tetex-texi2html-2.0.2-19.4.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"tetex-xdvi-2.0.2-19.4.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"xmltex-1.9-46.4.101mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.2", reference:"jadetex-3.12-106.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"tetex-3.0-8.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"tetex-afm-3.0-8.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"tetex-context-3.0-8.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"tetex-devel-3.0-8.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"tetex-doc-3.0-8.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"tetex-dvilj-3.0-8.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"tetex-dvipdfm-3.0-8.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"tetex-dvips-3.0-8.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"tetex-latex-3.0-8.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"tetex-mfwin-3.0-8.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"tetex-texi2html-3.0-8.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"tetex-xdvi-3.0-8.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"xmltex-1.9-54.1.102mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK2006.0", reference:"jadetex-3.12-110.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"tetex-3.0-12.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"tetex-afm-3.0-12.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"tetex-context-3.0-12.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"tetex-devel-3.0-12.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"tetex-doc-3.0-12.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"tetex-dvilj-3.0-12.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"tetex-dvipdfm-3.0-12.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"tetex-dvips-3.0-12.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"tetex-latex-3.0-12.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"tetex-mfwin-3.0-12.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"tetex-texi2html-3.0-12.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"tetex-xdvi-3.0-12.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"xmltex-1.9-58.1.20060mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
