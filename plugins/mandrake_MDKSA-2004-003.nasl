#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2004:003. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(14103);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/31 23:47:34 $");

  script_cve_id("CVE-2003-0988");
  script_xref(name:"MDKSA", value:"2004:003");

  script_name(english:"Mandrake Linux Security Advisory : kdepim (MDKSA-2004:003)");
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
"A vulnerability was discovered in all versions of kdepim as
distributed with KDE versions 3.1.0 through 3.1.4. This vulnerability
allows for a carefully crafted .VCF file to potentially enable a local
attacker to compromise the privacy of a victim's data or execute
arbitrary commands with the victim's privileges. This can also be used
by remote attackers if the victim enables previews for remote files;
however this is disabled by default.

The provided packages contain a patch from the KDE team to correct
this problem."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdepim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdepim-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdepim-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdepim-kaddressbook");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdepim-karm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdepim-knotes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdepim-korganizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdepim-kpilot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdepim2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdepim2-common-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdepim2-korganizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdepim2-korganizer-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdepim2-kpilot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdepim2-kpilot-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdepim2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdepim2-common-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdepim2-korganizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdepim2-korganizer-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdepim2-kpilot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdepim2-kpilot-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/01/14");
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
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"kdepim-3.1-17.1.91mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"kdepim-devel-3.1-17.1.91mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.2", reference:"kdepim-3.1.3-22.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"kdepim-common-3.1.3-22.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"kdepim-kaddressbook-3.1.3-22.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"kdepim-karm-3.1.3-22.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"kdepim-knotes-3.1.3-22.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"kdepim-korganizer-3.1.3-22.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"kdepim-kpilot-3.1.3-22.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64kdepim2-common-3.1.3-22.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64kdepim2-common-devel-3.1.3-22.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64kdepim2-korganizer-3.1.3-22.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64kdepim2-korganizer-devel-3.1.3-22.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64kdepim2-kpilot-3.1.3-22.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64kdepim2-kpilot-devel-3.1.3-22.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libkdepim2-common-3.1.3-22.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libkdepim2-common-devel-3.1.3-22.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libkdepim2-korganizer-3.1.3-22.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libkdepim2-korganizer-devel-3.1.3-22.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libkdepim2-kpilot-3.1.3-22.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libkdepim2-kpilot-devel-3.1.3-22.1.92mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
