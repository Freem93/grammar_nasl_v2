#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2009:311. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(42997);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/11/28 21:39:23 $");

  script_cve_id(
    "CVE-2007-6725",
    "CVE-2008-3520",
    "CVE-2008-3522",
    "CVE-2008-6679",
    "CVE-2009-0196",
    "CVE-2009-0583",
    "CVE-2009-0584",
    "CVE-2009-0792"
  );
  script_bugtraq_id(
    31470,
    34184,
    34337,
    34340,
    34445
  );
  script_osvdb_id(
    49890,
    49891,
    52988,
    53255,
    53492,
    53586,
    53618,
    56412
  );
  script_xref(name:"MDVSA", value:"2009:311");

  script_name(english:"Mandriva Linux Security Advisory : ghostscript (MDVSA-2009:311)");
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
"Multiple security vulnerabilities has been identified and fixed in
ghostscript :

A buffer underflow in Ghostscript's CCITTFax decoding filter allows
remote attackers to cause denial of service and possibly to execute
arbitrary by using a crafted PDF file (CVE-2007-6725).

Buffer overflow in Ghostscript's BaseFont writer module allows remote
attackers to cause a denial of service and possibly to execute
arbitrary code via a crafted Postscript file (CVE-2008-6679).

Multiple interger overflows in Ghostsript's International Color
Consortium Format Library (icclib) allows attackers to cause denial of
service (heap-based buffer overflow and application crash) and
possibly execute arbitrary code by using either a PostScript or PDF
file with crafte embedded images (CVE-2009-0583, CVE-2009-0584).

Multiple interger overflows in Ghostsript's International Color
Consortium Format Library (icclib) allows attackers to cause denial of
service (heap-based buffer overflow and application crash) and
possibly execute arbitrary code by using either a PostScript or PDF
file with crafte embedded images. Note: this issue exists because of
an incomplete fix for CVE-2009-0583 (CVE-2009-0792).

Heap-based overflow in Ghostscript's JBIG2 decoding library allows
attackers to cause denial of service and possibly to execute arbitrary
code by using a crafted PDF file (CVE-2009-0196).

Multiple integer overflows in JasPer 1.900.1 might allow
context-dependent attackers to have an unknown impact via a crafted
image file, related to integer multiplication for memory allocation
(CVE-2008-3520).

Buffer overflow in the jas_stream_printf function in
libjasper/base/jas_stream.c in JasPer 1.900.1 might allow
context-dependent attackers to have an unknown impact via vectors
related to the mif_hdr_put function and use of vsprintf
(CVE-2008-3522).

Previousely the ghostscript packages were statically built against a
bundled and private copy of the jasper library. This update makes
ghostscript link against the shared system jasper library which makes
it easier to address presumptive future security issues in the jasper
library.

Packages for 2008.0 are provided for Corporate Desktop 2008.0
customers

This update provides fixes for that vulnerabilities."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ghostscript-X");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ghostscript-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ghostscript-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ghostscript-dvipdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ghostscript-module-X");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gs8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gs8-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ijs1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ijs1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgs8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgs8-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libijs1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libijs1-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/04");
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
if (rpm_check(release:"MDK2008.0", reference:"ghostscript-8.60-55.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"ghostscript-X-8.60-55.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"ghostscript-common-8.60-55.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"ghostscript-doc-8.60-55.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"ghostscript-dvipdf-8.60-55.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"ghostscript-module-X-8.60-55.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64gs8-8.60-55.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64gs8-devel-8.60-55.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64ijs1-0.35-55.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64ijs1-devel-0.35-55.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libgs8-8.60-55.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libgs8-devel-8.60-55.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libijs1-0.35-55.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libijs1-devel-0.35-55.3mdv2008.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
