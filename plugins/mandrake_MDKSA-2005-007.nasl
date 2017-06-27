#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:007. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(16158);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/31 23:51:56 $");

  script_cve_id("CVE-2004-1025", "CVE-2004-1026");
  script_xref(name:"MDKSA", value:"2005:007");

  script_name(english:"Mandrake Linux Security Advisory : imlib (MDKSA-2005:007)");
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
"Pavel Kankovsky discovered several heap overflow flaw in the imlib
image handler. An attacker could create a carefully crafted image file
in such a way that it could cause an application linked with imlib to
execute arbitrary code when the file was opened by a user
(CVE-2004-1025).

As well, Pavel also discovered several integer overflows in imlib.
These could allow an attacker, creating a carefully crafted image
file, to cause an application linked with imlib to execute arbitrary
code or crash (CVE-2004-1026).

The updated packages have been patched to prevent these problems."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:imlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:imlib-cfgeditor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64imlib1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64imlib1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64imlib2_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64imlib2_1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64imlib2_1-filters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64imlib2_1-loaders");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libimlib1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libimlib1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libimlib2_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libimlib2_1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libimlib2_1-filters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libimlib2_1-loaders");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK10.0", reference:"imlib-1.9.14-8.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"imlib-cfgeditor-1.9.14-8.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64imlib1-1.9.14-8.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64imlib1-devel-1.9.14-8.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64imlib2_1-1.0.6-4.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64imlib2_1-devel-1.0.6-4.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64imlib2_1-filters-1.0.6-4.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64imlib2_1-loaders-1.0.6-4.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libimlib1-1.9.14-8.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libimlib1-devel-1.9.14-8.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libimlib2_1-1.0.6-4.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libimlib2_1-devel-1.0.6-4.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libimlib2_1-filters-1.0.6-4.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libimlib2_1-loaders-1.0.6-4.2.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.1", reference:"imlib-1.9.14-10.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"imlib-cfgeditor-1.9.14-10.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64imlib1-1.9.14-10.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64imlib1-devel-1.9.14-10.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64imlib2_1-1.1.0-4.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64imlib2_1-devel-1.1.0-4.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64imlib2_1-filters-1.1.0-4.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64imlib2_1-loaders-1.1.0-4.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libimlib1-1.9.14-10.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libimlib1-devel-1.9.14-10.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libimlib2_1-1.1.0-4.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libimlib2_1-devel-1.1.0-4.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libimlib2_1-filters-1.1.0-4.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libimlib2_1-loaders-1.1.0-4.1.101mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.2", reference:"imlib-1.9.14-8.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"imlib-cfgeditor-1.9.14-8.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64imlib1-1.9.14-8.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64imlib1-devel-1.9.14-8.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64imlib2_1-1.0.6-4.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64imlib2_1-devel-1.0.6-4.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64imlib2_1-filters-1.0.6-4.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64imlib2_1-loaders-1.0.6-4.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libimlib1-1.9.14-8.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libimlib1-devel-1.9.14-8.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libimlib2_1-1.0.6-4.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libimlib2_1-devel-1.0.6-4.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libimlib2_1-filters-1.0.6-4.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libimlib2_1-loaders-1.0.6-4.2.92mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
