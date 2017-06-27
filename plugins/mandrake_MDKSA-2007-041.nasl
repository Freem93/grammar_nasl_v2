#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2007:041. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(24654);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/02/16 22:37:06 $");

  script_cve_id("CVE-2007-0770");
  script_bugtraq_id(20707);
  script_osvdb_id(31911);
  script_xref(name:"MDKSA", value:"2007:041");

  script_name(english:"Mandrake Linux Security Advisory : ImageMagick (MDKSA-2007:041)");
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
"Vladimir Nadvornik discovered a buffer overflow in GraphicsMagick and
ImageMagick allows user-assisted attackers to cause a denial of
service and possibly execute execute arbitrary code via a PALM image
that is not properly handled by the ReadPALMImage function in
coders/palm.c.

This is related to an earlier fix for CVE-2006-5456 that did not fully
correct the issue.

Updated packages have been patched to correct this issue."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ImageMagick-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64Magick10.4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64Magick10.4.0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64Magick8.4.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64Magick8.4.2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libMagick10.4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libMagick10.4.0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libMagick8.4.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libMagick8.4.2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:perl-Image-Magick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2006.0", reference:"ImageMagick-6.2.4.3-1.5.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"ImageMagick-doc-6.2.4.3-1.5.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64Magick8.4.2-6.2.4.3-1.5.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64Magick8.4.2-devel-6.2.4.3-1.5.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libMagick8.4.2-6.2.4.3-1.5.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libMagick8.4.2-devel-6.2.4.3-1.5.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"perl-Image-Magick-6.2.4.3-1.5.20060mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK2007.0", reference:"ImageMagick-6.2.9.2-1.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"ImageMagick-doc-6.2.9.2-1.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64Magick10.4.0-6.2.9.2-1.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64Magick10.4.0-devel-6.2.9.2-1.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libMagick10.4.0-6.2.9.2-1.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libMagick10.4.0-devel-6.2.9.2-1.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"perl-Image-Magick-6.2.9.2-1.2mdv2007.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
