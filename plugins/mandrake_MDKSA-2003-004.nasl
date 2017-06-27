#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2003:004. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(13989);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/31 23:47:33 $");

  script_cve_id("CVE-2002-1393");
  script_xref(name:"MDKSA", value:"2003:004-1");

  script_name(english:"Mandrake Linux Security Advisory : kde (MDKSA-2003:004-1)");
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
"Multiple instances of improperly quoted shell command execution exist
in KDE 2.x up to and including KDE 3.0.5. KDE fails to properly quote
parameters of instructions passed to the shell for execution. These
parameters may contain data such as filenames, URLs, email address,
and so forth; this data may be provided remotely to a victim via
email, web pages, files on a network filesystem, or other untrusted
sources.

It is possible for arbitrary command execution on a vulnerable system
with the privileges of the victim's account.

The code audit by the KDE team resulted in patches for KDE 2.2.2 and
KDE 3; version 3.0.5a was released and the KDE team encourages the
upgrade. The listed KDE2 packages have the KDE team's patches applied
to provide the fixed code.

Update :

The SRPM for the new arts for Mandrake Linux 9.0 was not linked into
the updates tree. This has been corrected."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kde.org/info/security/advisory-20021220-1.txt"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:arts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdeaddons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdeadmin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdeartwork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-nsplugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdeedu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdegames");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdegames-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdegraphics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdegraphics-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdelibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdelibs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdemultimedia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdemultimedia-aktion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdemultimedia-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdenetwork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdenetwork-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdepim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdepim-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdesdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdesdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdetoys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdetoys-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdeutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdeutils-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libarts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libarts-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"arts-1.0.5a-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"kdeaddons-3.0.5a-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"kdeadmin-3.0.5a-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"kdeartwork-3.0.5a-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"kdebase-3.0.5a-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"kdebase-devel-3.0.5a-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"kdebase-nsplugins-3.0.5a-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"kdeedu-3.0.5a-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"kdegames-3.0.5a-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"kdegames-devel-3.0.5a-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"kdegraphics-3.0.5a-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"kdegraphics-devel-3.0.5a-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"kdelibs-3.0.5a-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"kdelibs-devel-3.0.5a-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"kdemultimedia-3.0.5a-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"kdemultimedia-aktion-3.0.5a-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"kdemultimedia-devel-3.0.5a-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"kdenetwork-3.0.5a-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"kdenetwork-devel-3.0.5a-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"kdepim-3.0.5a-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"kdepim-devel-3.0.5a-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"kdesdk-3.0.5a-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"kdesdk-devel-3.0.5a-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"kdetoys-3.0.5a-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"kdetoys-devel-3.0.5a-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"kdeutils-3.0.5a-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"kdeutils-devel-3.0.5a-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"libarts-1.0.5a-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"libarts-devel-1.0.5a-1.1mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
