#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2012:106. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(61959);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/06/01 00:27:16 $");

  script_cve_id("CVE-2012-2812", "CVE-2012-2813", "CVE-2012-2814", "CVE-2012-2836", "CVE-2012-2837", "CVE-2012-2840", "CVE-2012-2841");
  script_xref(name:"MDVSA", value:"2012:106");

  script_name(english:"Mandriva Linux Security Advisory : libexif (MDVSA-2012:106)");
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
libexif :

A heap-based out-of-bounds array read in the exif_entry_get_value
function in libexif/exif-entry.c in libexif 0.6.20 and earlier allows
remote attackers to cause a denial of service or possibly obtain
potentially sensitive information from process memory via an image
with crafted EXIF tags (CVE-2012-2812).

A heap-based out-of-bounds array read in the
exif_convert_utf16_to_utf8 function in libexif/exif-entry.c in libexif
0.6.20 and earlier allows remote attackers to cause a denial of
service or possibly obtain potentially sensitive information from
process memory via an image with crafted EXIF tags (CVE-2012-2813).

A buffer overflow in the exif_entry_format_value function in
libexif/exif-entry.c in libexif 0.6.20 allows remote attackers to
cause a denial of service or possibly execute arbitrary code via an
image with crafted EXIF tags (CVE-2012-2814).

A heap-based out-of-bounds array read in the exif_data_load_data
function in libexif 0.6.20 and earlier allows remote attackers to
cause a denial of service or possibly obtain potentially sensitive
information from process memory via an image with crafted EXIF tags
(CVE-2012-2836).

A divide-by-zero error in the mnote_olympus_entry_get_value function
while formatting EXIF maker note tags in libexif 0.6.20 and earlier
allows remote attackers to cause a denial of service via an image with
crafted EXIF tags (CVE-2012-2837).

An off-by-one error in the exif_convert_utf16_to_utf8 function in
libexif/exif-entry.c in libexif 0.6.20 and earlier allows remote
attackers to cause a denial of service or possibly execute arbitrary
code via an image with crafted EXIF tags (CVE-2012-2840).

An integer underflow in the exif_entry_get_value function can cause a
heap overflow and potentially arbitrary code execution while
formatting an EXIF tag, if the function is called with a buffer size
parameter equal to zero or one (CVE-2012-2841).

The updated packages have been upgraded to the 0.6.21 version which is
not vulnerable to these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://sourceforge.net/mailarchive/message.php?msg_id=29534027"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64exif-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64exif12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libexif-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libexif12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libexif12-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2011");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64exif-devel-0.6.21-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64exif12-0.6.21-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libexif-devel-0.6.21-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libexif12-0.6.21-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libexif12-common-0.6.21-0.1-mdv2011.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
