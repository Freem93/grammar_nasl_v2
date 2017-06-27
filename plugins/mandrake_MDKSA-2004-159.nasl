#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2004:159. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(16076);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/31 23:51:56 $");

  script_cve_id("CVE-2004-0968", "CVE-2004-1382");
  script_xref(name:"MDKSA", value:"2004:159");

  script_name(english:"Mandrake Linux Security Advisory : glibc (MDKSA-2004:159)");
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
"The Trustix developers discovered that the catchsegv and glibcbug
utilities, part of the glibc package, created temporary files in an
insecure manner. This could allow for a symlink attack to create or
overwrite arbitrary files with the privileges of the user invoking the
program.

The updated packages have been patched to correct this issue."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:glibc-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:glibc-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:glibc-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:glibc-i18ndata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:glibc-profile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:glibc-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ldconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nptl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nscd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:timezone");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/12/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/02");
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
if (rpm_check(release:"MDK10.0", reference:"glibc-2.3.3-12.8.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"glibc-debug-2.3.3-12.8.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"glibc-devel-2.3.3-12.8.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"glibc-doc-2.3.3-12.8.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"glibc-doc-pdf-2.3.3-12.8.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"glibc-i18ndata-2.3.3-12.8.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"glibc-profile-2.3.3-12.8.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"glibc-static-devel-2.3.3-12.8.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"glibc-utils-2.3.3-12.8.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"ldconfig-2.3.3-12.8.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"nptl-devel-2.3.3-12.8.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"nscd-2.3.3-12.8.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"timezone-2.3.3-12.8.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.1", reference:"glibc-2.3.3-23.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"glibc-debug-2.3.3-23.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"glibc-devel-2.3.3-23.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"glibc-doc-2.3.3-23.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"glibc-doc-pdf-2.3.3-23.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"glibc-i18ndata-2.3.3-23.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"glibc-profile-2.3.3-23.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"glibc-static-devel-2.3.3-23.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"glibc-utils-2.3.3-23.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"ldconfig-2.3.3-23.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"nptl-devel-2.3.3-23.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"nscd-2.3.3-23.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"timezone-2.3.3-23.1.101mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
