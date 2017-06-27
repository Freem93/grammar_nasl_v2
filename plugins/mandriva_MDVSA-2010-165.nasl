#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2010:165. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(48933);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/17 17:02:54 $");

  script_cve_id("CVE-2010-2947");
  script_bugtraq_id(42592);
  script_xref(name:"MDVSA", value:"2010:165");

  script_name(english:"Mandriva Linux Security Advisory : libHX (MDVSA-2010:165)");
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
"A vulnerability has been found and corrected in libHX :

Heap-based buffer overflow in the HX_split function in string.c in
libHX before 3.6 allows remote attackers to execute arbitrary code or
cause a denial of service (application crash) via a string that is
inconsistent with the expected number of fields (CVE-2010-2947).

The updated packages have been patched to correct this issue."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64HX-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64HX14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64HX18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64HX22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libHX-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libHX14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libHX18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libHX22");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/31");
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
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64HX-devel-1.25-1.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64HX14-1.25-1.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libHX-devel-1.25-1.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libHX14-1.25-1.1mdv2009.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64HX-devel-2.5-1.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64HX18-2.5-1.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libHX-devel-2.5-1.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libHX18-2.5-1.1mdv2009.1", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64HX-devel-3.1-1.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64HX22-3.1-1.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libHX-devel-3.1-1.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libHX22-3.1-1.1mdv2010.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64HX-devel-3.4-1.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64HX22-3.4-1.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libHX-devel-3.4-1.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libHX22-3.4-1.1mdv2010.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");