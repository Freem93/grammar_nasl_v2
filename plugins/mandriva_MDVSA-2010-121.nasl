#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2010:121. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(47115);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2013/06/01 00:15:50 $");

  script_cve_id("CVE-2010-0421");
  script_bugtraq_id(38760);
  script_xref(name:"MDVSA", value:"2010:121");

  script_name(english:"Mandriva Linux Security Advisory : pango (MDVSA-2010:121)");
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
"A vulnerability has been discovered and corrected in pango :

Array index error in the hb_ot_layout_build_glyph_classes function in
pango/opentype/hb-ot-layout.cc in Pango before 1.27.1 allows
context-dependent attackers to cause a denial of service (application
crash) via a crafted font file, related to building a synthetic Glyph
Definition (aka GDEF) table by using this font's charmap and the
Unicode property database (CVE-2010-0421).

Packages for 2008.0 and 2009.0 are provided as of the Extended
Maintenance Program. Please visit this link to learn more:
http://store.mandriva.com/product_info.php?cPath=149&amp;products_id=4
90

The updated packages have been patched to correct this issue."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64pango1.0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64pango1.0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64pango1.0_0-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpango1.0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpango1.0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpango1.0_0-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:pango");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:pango-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/23");
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
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64pango1.0-devel-1.18.2-1.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64pango1.0_0-1.18.2-1.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64pango1.0_0-modules-1.18.2-1.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libpango1.0-devel-1.18.2-1.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libpango1.0_0-1.18.2-1.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libpango1.0_0-modules-1.18.2-1.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"pango-1.18.2-1.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"pango-doc-1.18.2-1.2mdv2008.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64pango1.0-devel-1.22.0-1.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64pango1.0_0-1.22.0-1.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64pango1.0_0-modules-1.22.0-1.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libpango1.0-devel-1.22.0-1.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libpango1.0_0-1.22.0-1.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libpango1.0_0-modules-1.22.0-1.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"pango-1.22.0-1.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"pango-doc-1.22.0-1.2mdv2009.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64pango1.0-devel-1.24.1-1.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64pango1.0_0-1.24.1-1.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64pango1.0_0-modules-1.24.1-1.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libpango1.0-devel-1.24.1-1.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libpango1.0_0-1.24.1-1.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libpango1.0_0-modules-1.24.1-1.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"pango-1.24.1-1.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"pango-doc-1.24.1-1.1mdv2009.1", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64pango1.0-devel-1.26.1-1.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64pango1.0_0-1.26.1-1.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64pango1.0_0-modules-1.26.1-1.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libpango1.0-devel-1.26.1-1.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libpango1.0_0-1.26.1-1.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libpango1.0_0-modules-1.26.1-1.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"pango-1.26.1-1.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"pango-doc-1.26.1-1.2mdv2010.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
