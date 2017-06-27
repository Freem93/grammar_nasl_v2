#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2011:017. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(51808);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/03/07 17:48:16 $");

  script_cve_id("CVE-2010-2642");
  script_bugtraq_id(45678);
  script_osvdb_id(70302);
  script_xref(name:"MDVSA", value:"2011:017");

  script_name(english:"Mandriva Linux Security Advisory : tetex (MDVSA-2011:017)");
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
"It was discovered that tetex suffered from the same vulnerability as
previousely addressed in Evince with MDVSA-2011:005 (CVE-2010-2642).
As a precaution tetex has been patched to address this flaw.

Packages for 2009.0 are provided as of the Extended Maintenance
Program. Please visit this link to learn more:
http://store.mandriva.com/product_info.php?cPath=149 products_id=490"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-usrlocal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-xdvi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xmltex");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2009.0", reference:"jadetex-3.12-145.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"tetex-3.0-47.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"tetex-afm-3.0-47.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"tetex-context-3.0-47.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"tetex-devel-3.0-47.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"tetex-doc-3.0-47.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"tetex-dvilj-3.0-47.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"tetex-dvipdfm-3.0-47.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"tetex-dvips-3.0-47.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"tetex-latex-3.0-47.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"tetex-mfwin-3.0-47.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"tetex-texi2html-3.0-47.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"tetex-usrlocal-3.0-47.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"tetex-xdvi-3.0-47.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"xmltex-1.9-93.2mdv2009.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2010.0", reference:"jadetex-3.12-147.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"tetex-3.0-49.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"tetex-afm-3.0-49.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"tetex-context-3.0-49.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"tetex-devel-3.0-49.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"tetex-doc-3.0-49.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"tetex-dvilj-3.0-49.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"tetex-dvipdfm-3.0-49.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"tetex-dvips-3.0-49.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"tetex-latex-3.0-49.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"tetex-mfwin-3.0-49.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"tetex-texi2html-3.0-49.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"tetex-usrlocal-3.0-49.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"tetex-xdvi-3.0-49.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"xmltex-1.9-95.2mdv2010.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2010.1", reference:"jadetex-3.12-149.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"tetex-3.0-51.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"tetex-afm-3.0-51.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"tetex-context-3.0-51.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"tetex-devel-3.0-51.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"tetex-doc-3.0-51.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"tetex-dvilj-3.0-51.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"tetex-dvipdfm-3.0-51.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"tetex-dvips-3.0-51.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"tetex-latex-3.0-51.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"tetex-mfwin-3.0-51.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"tetex-texi2html-3.0-51.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"tetex-usrlocal-3.0-51.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"tetex-xdvi-3.0-51.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"xmltex-1.9-97.1mdv2010.2", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
