#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2010:149. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(48319);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/05/20 14:12:05 $");

  script_cve_id("CVE-2010-1797");
  script_bugtraq_id(42241);
  script_xref(name:"MDVSA", value:"2010:149");

  script_name(english:"Mandriva Linux Security Advisory : freetype2 (MDVSA-2010:149)");
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
"A vulnerability has been discovered and corrected in freetype2 :

Multiple stack overflow flaws have been reported in the way FreeType
font rendering engine processed certain CFF opcodes. An attacker could
use these flaws to create a specially crafted font file that, when
opened, would cause an application linked against libfreetype to
crash, or, possibly execute arbitrary code (CVE-2010-1797).

Packages for 2008.0 and 2009.0 are provided as of the Extended
Maintenance Program. Please visit this link to learn more:
http://store.mandriva.com/product_info.php?cPath=149&amp;products_id=4
90

The updated packages have been patched to correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=621144"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64freetype6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64freetype6-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64freetype6-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libfreetype6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libfreetype6-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libfreetype6-static-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64freetype6-2.3.5-2.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64freetype6-devel-2.3.5-2.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64freetype6-static-devel-2.3.5-2.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libfreetype6-2.3.5-2.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libfreetype6-devel-2.3.5-2.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libfreetype6-static-devel-2.3.5-2.4mdv2008.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64freetype6-2.3.7-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64freetype6-devel-2.3.7-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64freetype6-static-devel-2.3.7-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libfreetype6-2.3.7-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libfreetype6-devel-2.3.7-1.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libfreetype6-static-devel-2.3.7-1.3mdv2009.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64freetype6-2.3.9-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64freetype6-devel-2.3.9-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64freetype6-static-devel-2.3.9-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libfreetype6-2.3.9-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libfreetype6-devel-2.3.9-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libfreetype6-static-devel-2.3.9-1.4mdv2009.1", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64freetype6-2.3.11-1.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64freetype6-devel-2.3.11-1.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64freetype6-static-devel-2.3.11-1.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libfreetype6-2.3.11-1.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libfreetype6-devel-2.3.11-1.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libfreetype6-static-devel-2.3.11-1.2mdv2010.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64freetype6-2.3.12-1.2mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64freetype6-devel-2.3.12-1.2mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64freetype6-static-devel-2.3.12-1.2mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libfreetype6-2.3.12-1.2mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libfreetype6-devel-2.3.12-1.2mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libfreetype6-static-devel-2.3.12-1.2mdv2010.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
