#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2006:054. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(21037);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/05/31 23:56:38 $");

  script_cve_id("CVE-2006-0746");
  script_xref(name:"MDKSA", value:"2006:054");

  script_name(english:"Mandrake Linux Security Advisory : kdegraphics (MDKSA-2006:054)");
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
"Marcelo Ricardo Leitner discovered the official published kpdf patches
for several previous xpdf vulnerabilities were lacking some hunks
published by upstream xpdf. As a result, kpdf is still vulnerable to
certain carefully crafted pdf files.

Although previous updates captured most of these changes, this new
update picks up some of the missing patches.

The updated packages have been patched to correct these problems."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdegraphics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdegraphics-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdegraphics-kdvi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdegraphics-kfax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdegraphics-kghostview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdegraphics-kiconedit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdegraphics-kolourpaint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdegraphics-kooka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdegraphics-kpaint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdegraphics-kpdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdegraphics-kpovmodeler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdegraphics-kruler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdegraphics-ksnapshot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdegraphics-ksvg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdegraphics-kuickshow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdegraphics-kview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdegraphics-mrmlsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdegraphics0-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdegraphics0-common-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdegraphics0-kghostview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdegraphics0-kghostview-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdegraphics0-kooka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdegraphics0-kooka-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdegraphics0-kpovmodeler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdegraphics0-kpovmodeler-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdegraphics0-ksvg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdegraphics0-ksvg-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdegraphics0-kuickshow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdegraphics0-kview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdegraphics0-kview-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdegraphics0-mrmlsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdegraphics0-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdegraphics0-common-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdegraphics0-kghostview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdegraphics0-kghostview-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdegraphics0-kooka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdegraphics0-kooka-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdegraphics0-kpovmodeler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdegraphics0-kpovmodeler-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdegraphics0-ksvg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdegraphics0-ksvg-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdegraphics0-kuickshow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdegraphics0-kview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdegraphics0-kview-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdegraphics0-mrmlsearch");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/03/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2006.0", reference:"kdegraphics-3.4.2-11.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"kdegraphics-common-3.4.2-11.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"kdegraphics-kdvi-3.4.2-11.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"kdegraphics-kfax-3.4.2-11.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"kdegraphics-kghostview-3.4.2-11.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"kdegraphics-kiconedit-3.4.2-11.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"kdegraphics-kolourpaint-3.4.2-11.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"kdegraphics-kooka-3.4.2-11.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"kdegraphics-kpaint-3.4.2-11.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"kdegraphics-kpdf-3.4.2-11.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"kdegraphics-kpovmodeler-3.4.2-11.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"kdegraphics-kruler-3.4.2-11.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"kdegraphics-ksnapshot-3.4.2-11.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"kdegraphics-ksvg-3.4.2-11.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"kdegraphics-kuickshow-3.4.2-11.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"kdegraphics-kview-3.4.2-11.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"kdegraphics-mrmlsearch-3.4.2-11.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64kdegraphics0-common-3.4.2-11.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64kdegraphics0-common-devel-3.4.2-11.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64kdegraphics0-kghostview-3.4.2-11.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64kdegraphics0-kghostview-devel-3.4.2-11.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64kdegraphics0-kooka-3.4.2-11.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64kdegraphics0-kooka-devel-3.4.2-11.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64kdegraphics0-kpovmodeler-3.4.2-11.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64kdegraphics0-kpovmodeler-devel-3.4.2-11.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64kdegraphics0-ksvg-3.4.2-11.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64kdegraphics0-ksvg-devel-3.4.2-11.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64kdegraphics0-kuickshow-3.4.2-11.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64kdegraphics0-kview-3.4.2-11.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64kdegraphics0-kview-devel-3.4.2-11.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64kdegraphics0-mrmlsearch-3.4.2-11.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libkdegraphics0-common-3.4.2-11.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libkdegraphics0-common-devel-3.4.2-11.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libkdegraphics0-kghostview-3.4.2-11.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libkdegraphics0-kghostview-devel-3.4.2-11.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libkdegraphics0-kooka-3.4.2-11.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libkdegraphics0-kooka-devel-3.4.2-11.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libkdegraphics0-kpovmodeler-3.4.2-11.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libkdegraphics0-kpovmodeler-devel-3.4.2-11.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libkdegraphics0-ksvg-3.4.2-11.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libkdegraphics0-ksvg-devel-3.4.2-11.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libkdegraphics0-kuickshow-3.4.2-11.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libkdegraphics0-kview-3.4.2-11.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libkdegraphics0-kview-devel-3.4.2-11.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libkdegraphics0-mrmlsearch-3.4.2-11.6.20060mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
