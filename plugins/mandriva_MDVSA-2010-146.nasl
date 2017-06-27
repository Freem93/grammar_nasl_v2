#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2010:146. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(48272);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2013/06/01 00:15:50 $");

  script_cve_id("CVE-2010-1411", "CVE-2010-2065", "CVE-2010-2067", "CVE-2010-2233", "CVE-2010-2481", "CVE-2010-2482", "CVE-2010-2483", "CVE-2010-2595", "CVE-2010-2597");
  script_bugtraq_id(40823, 41011, 41012, 41088, 41295, 41480);
  script_xref(name:"MDVSA", value:"2010:146");

  script_name(english:"Mandriva Linux Security Advisory : libtiff (MDVSA-2010:146)");
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
"Multiple vulnerabilities has been discovered and corrected in 
libtiff :

The TIFFYCbCrtoRGB function in LibTIFF 3.9.0 and 3.9.2, as used in
ImageMagick, does not properly handle invalid ReferenceBlackWhite
values, which allows remote attackers to cause a denial of service
(application crash) via a crafted TIFF image that triggers an array
index error, related to downsampled OJPEG input. (CVE-2010-2595)

Multiple integer overflows in the Fax3SetupState function in
tif_fax3.c in the FAX3 decoder in LibTIFF before 3.9.3 allow remote
attackers to execute arbitrary code or cause a denial of service
(application crash) via a crafted TIFF file that triggers a heap-based
buffer overflow (CVE-2010-1411).

Integer overflow in the TIFFroundup macro in LibTIFF before 3.9.3
allows remote attackers to cause a denial of service (application
crash) or possibly execute arbitrary code via a crafted TIFF file that
triggers a buffer overflow (CVE-2010-2065).

The TIFFRGBAImageGet function in LibTIFF 3.9.0 allows remote attackers
to cause a denial of service (out-of-bounds read and application
crash) via a TIFF file with an invalid combination of SamplesPerPixel
and Photometric values (CVE-2010-2483).

The TIFFVStripSize function in tif_strip.c in LibTIFF 3.9.0 and 3.9.2
makes incorrect calls to the TIFFGetField function, which allows
remote attackers to cause a denial of service (application crash) via
a crafted TIFF image, related to downsampled OJPEG input and possibly
related to a compiler optimization that triggers a divide-by-zero
error (CVE-2010-2597).

The TIFFExtractData macro in LibTIFF before 3.9.4 does not properly
handle unknown tag types in TIFF directory entries, which allows
remote attackers to cause a denial of service (out-of-bounds read and
application crash) via a crafted TIFF file (CVE-2010-248).

Stack-based buffer overflow in the TIFFFetchSubjectDistance function
in tif_dirread.c in LibTIFF before 3.9.4 allows remote attackers to
cause a denial of service (application crash) or possibly execute
arbitrary code via a long EXIF SubjectDistance field in a TIFF file
(CVE-2010-2067).

tif_getimage.c in LibTIFF 3.9.0 and 3.9.2 on 64-bit platforms, as used
in ImageMagick, does not properly perform vertical flips, which allows
remote attackers to cause a denial of service (application crash) or
possibly execute arbitrary code via a crafted TIFF image, related to
downsampled OJPEG input. (CVE-2010-2233).

LibTIFF 3.9.4 and earlier does not properly handle an invalid
td_stripbytecount field, which allows remote attackers to cause a
denial of service (NULL pointer dereference and application crash) via
a crafted TIFF file, a different vulnerability than CVE-2010-2443
(CVE-2010-2482).

The updated packages have been patched to correct these issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64tiff-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64tiff-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64tiff3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libtiff-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libtiff-progs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libtiff-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libtiff3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64tiff-devel-3.9.1-4.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64tiff-static-devel-3.9.1-4.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64tiff3-3.9.1-4.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libtiff-devel-3.9.1-4.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"libtiff-progs-3.9.1-4.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libtiff-static-devel-3.9.1-4.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libtiff3-3.9.1-4.1mdv2010.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64tiff-devel-3.9.2-2.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64tiff-static-devel-3.9.2-2.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64tiff3-3.9.2-2.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libtiff-devel-3.9.2-2.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"libtiff-progs-3.9.2-2.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libtiff-static-devel-3.9.2-2.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libtiff3-3.9.2-2.1mdv2010.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
