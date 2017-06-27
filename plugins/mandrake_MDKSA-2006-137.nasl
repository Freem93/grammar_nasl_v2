#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2006:137. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(23886);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/09/26 13:31:37 $");

  script_cve_id("CVE-2006-3459", "CVE-2006-3460", "CVE-2006-3461", "CVE-2006-3462", "CVE-2006-3463", "CVE-2006-3464", "CVE-2006-3465");
  script_xref(name:"MDKSA", value:"2006:137");

  script_name(english:"Mandrake Linux Security Advisory : libtiff (MDKSA-2006:137)");
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
"Tavis Ormandy, Google Security Team, discovered several
vulnerabilities the libtiff image processing library :

Several buffer overflows have been discovered, including a stack
buffer overflow via TIFFFetchShortPair() in tif_dirread.c, which is
used to read two unsigned shorts from the input file. While a bounds
check is performed via CheckDirCount(), no action is taken on the
result allowing a pathological tdir_count to read an arbitrary number
of unsigned shorts onto a stack buffer. (CVE-2006-3459)

A heap overflow vulnerability was discovered in the jpeg decoder,
where TIFFScanLineSize() is documented to return the size in bytes
that a subsequent call to TIFFReadScanline() would write, however the
encoded jpeg stream may disagree with these results and overrun the
buffer with more data than expected. (CVE-2006-3460)

Another heap overflow exists in the PixarLog decoder where a run
length encoded data stream may specify a stride that is not an exact
multiple of the number of samples. The result is that on the final
decode operation the destination buffer is overrun, potentially
allowing an attacker to execute arbitrary code. (CVE-2006-3461)

The NeXT RLE decoder was also vulnerable to a heap overflow
vulnerability, where no bounds checking was performed on the result of
certain RLE decoding operations. This was solved by ensuring the
number of pixels written did not exceed the size of the scanline
buffer already prepared. (CVE-2006-3462)

An infinite loop was discovered in EstimateStripByteCounts(), where a
16bit unsigned short was used to iterate over a 32bit unsigned value,
should the unsigned int (td_nstrips) have exceeded USHORT_MAX, the
loop would never terminate and continue forever. (CVE-2006-3463)

Multiple unchecked arithmetic operations were uncovered, including a
number of the range checking operations deisgned to ensure the offsets
specified in tiff directories are legitimate. These can be caused to
wrap for extreme values, bypassing sanity checks. Additionally, a
number of codepaths were uncovered where assertions did not hold true,
resulting in the client application calling abort(). (CVE-2006-3464)

A flaw was also uncovered in libtiffs custom tag support, as
documented here http://www.libtiff.org/v3.6.0.html. While well formed
tiff files must have correctly ordered directories, libtiff attempts
to support broken images that do not. However in certain
circumstances, creating anonymous fields prior to merging field
information from codec information can result in recognised fields
with unexpected values. This state results in abnormal behaviour,
crashes, or potentially arbitrary code execution. (CVE-2006-3465)

The updated packages have been patched to correct these issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apple iOS MobileMail LibTIFF Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64tiff3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64tiff3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64tiff3-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libtiff-progs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libtiff3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libtiff3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libtiff3-static-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/12/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64tiff3-3.6.1-12.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64tiff3-devel-3.6.1-12.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64tiff3-static-devel-3.6.1-12.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"libtiff-progs-3.6.1-12.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libtiff3-3.6.1-12.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libtiff3-devel-3.6.1-12.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libtiff3-static-devel-3.6.1-12.6.20060mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
