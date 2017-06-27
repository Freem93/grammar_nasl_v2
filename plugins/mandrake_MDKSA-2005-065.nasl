#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:065. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(17677);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2014/04/15 10:48:38 $");

  script_cve_id("CVE-2005-0005", "CVE-2005-0397", "CVE-2005-0759", "CVE-2005-0760", "CVE-2005-0761", "CVE-2005-0762");
  script_xref(name:"MDKSA", value:"2005:065");

  script_name(english:"Mandrake Linux Security Advisory : ImageMagick (MDKSA-2005:065)");
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
"A format string vulnerability was discovered in ImageMagick, in the
way it handles filenames. An attacker could execute arbitrary code on
a victim's machine provided they could trick them into opening a file
with a special name (CVE-2005-0397).

As well, Andrei Nigmatulin discovered a heap-based buffer overflow in
ImageMagick's image handler. An attacker could create a special
PhotoShop Document (PSD) image file in such a way that it would cause
ImageMagick to execute arbitrary code when processing the image
(CVE-2005-0005).

Other vulnerabilities were discovered in ImageMagick versions prior to
6.0 :

A bug in the way that ImageMagick handles TIFF tags was discovered. It
was possible that a TIFF image with an invalid tag could cause
ImageMagick to crash (CVE-2005-0759).

A bug in ImageMagick's TIFF decoder was discovered where a specially-
crafted TIFF image could cause ImageMagick to crash (CVE-2005-0760).

A bug in ImageMagick's PSD parsing was discovered where a specially-
crafted PSD file could cause ImageMagick to crash (CVE-2005-0761).

Finally, a heap overflow bug was discovered in ImageMagick's SGI
parser. If an attacker could trick a user into opening a specially-
crafted SGI image file, ImageMagick would execute arbitrary code
(CVE-2005-0762).

The updated packages have been patched to correct these issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ImageMagick-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64Magick5.5.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64Magick5.5.7-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64Magick6.4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64Magick6.4.0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libMagick5.5.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libMagick5.5.7-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libMagick6.4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libMagick6.4.0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:perl-Magick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK10.0", reference:"ImageMagick-5.5.7.15-6.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"ImageMagick-doc-5.5.7.15-6.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64Magick5.5.7-5.5.7.15-6.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64Magick5.5.7-devel-5.5.7.15-6.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libMagick5.5.7-5.5.7.15-6.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libMagick5.5.7-devel-5.5.7.15-6.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"perl-Magick-5.5.7.15-6.3.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.1", reference:"ImageMagick-6.0.4.4-5.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"ImageMagick-doc-6.0.4.4-5.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64Magick6.4.0-6.0.4.4-5.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64Magick6.4.0-devel-6.0.4.4-5.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libMagick6.4.0-6.0.4.4-5.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libMagick6.4.0-devel-6.0.4.4-5.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"perl-Magick-6.0.4.4-5.2.101mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
