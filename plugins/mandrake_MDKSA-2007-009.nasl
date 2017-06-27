#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2007:009. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(24625);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/05/31 23:56:40 $");

  script_cve_id("CVE-2006-6811");
  script_xref(name:"MDKSA", value:"2007:009");

  script_name(english:"Mandrake Linux Security Advisory : kdenetwork (MDKSA-2007:009)");
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
"KsIRC 1.3.12 allows remote attackers to cause a denial of service
(crash) via a long PRIVMSG string when connecting to an Internet Relay
Chat (IRC) server, which causes an assertion failure and results in a
NULL pointer dereference.

Updated packages are patched to address this issue."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdenetwork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdenetwork-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdenetwork-kdict");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdenetwork-kget");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdenetwork-knewsticker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdenetwork-kopete");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdenetwork-kopete-latex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdenetwork-kppp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdenetwork-kppp-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdenetwork-krfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdenetwork-ksirc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdenetwork-ktalk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdenetwork-kwifimanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdenetwork2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdenetwork2-common-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdenetwork2-kdict");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdenetwork2-knewsticker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdenetwork2-kopete");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdenetwork2-kopete-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdenetwork2-ksirc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdenetwork2-kwifimanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdenetwork2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdenetwork2-common-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdenetwork2-kdict");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdenetwork2-knewsticker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdenetwork2-kopete");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdenetwork2-kopete-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdenetwork2-ksirc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdenetwork2-kwifimanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lisa");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2007.0", reference:"kdenetwork-3.5.4-3.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"kdenetwork-common-3.5.4-3.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"kdenetwork-kdict-3.5.4-3.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"kdenetwork-kget-3.5.4-3.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"kdenetwork-knewsticker-3.5.4-3.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"kdenetwork-kopete-3.5.4-3.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"kdenetwork-kopete-latex-3.5.4-3.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"kdenetwork-kppp-3.5.4-3.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"kdenetwork-kppp-provider-3.5.4-3.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"kdenetwork-krfb-3.5.4-3.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"kdenetwork-ksirc-3.5.4-3.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"kdenetwork-ktalk-3.5.4-3.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"kdenetwork-kwifimanager-3.5.4-3.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64kdenetwork2-common-3.5.4-3.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64kdenetwork2-common-devel-3.5.4-3.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64kdenetwork2-kdict-3.5.4-3.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64kdenetwork2-knewsticker-3.5.4-3.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64kdenetwork2-kopete-3.5.4-3.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64kdenetwork2-kopete-devel-3.5.4-3.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64kdenetwork2-ksirc-3.5.4-3.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64kdenetwork2-kwifimanager-3.5.4-3.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libkdenetwork2-common-3.5.4-3.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libkdenetwork2-common-devel-3.5.4-3.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libkdenetwork2-kdict-3.5.4-3.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libkdenetwork2-knewsticker-3.5.4-3.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libkdenetwork2-kopete-3.5.4-3.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libkdenetwork2-kopete-devel-3.5.4-3.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libkdenetwork2-ksirc-3.5.4-3.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libkdenetwork2-kwifimanager-3.5.4-3.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"lisa-3.5.4-3.1mdv2007.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
