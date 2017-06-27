#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:079. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(18172);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/31 23:51:57 $");

  script_cve_id("CVE-2005-0448");
  script_xref(name:"MDKSA", value:"2005:079");

  script_name(english:"Mandrake Linux Security Advisory : perl (MDKSA-2005:079)");
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
"Paul Szabo discovered another vulnerability in the rmtree() function
in File::Path.pm. While a process running as root (or another user)
was busy deleting a directory tree, a different user could exploit a
race condition to create setuid binaries in this directory tree,
provided that he already had write permissions in any subdirectory of
that tree.

The provided packages have been patched to resolve this problem."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:perl-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:perl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:perl-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:mandrakesoft:mandrake_linux:le2005");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/05/02");
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
if (rpm_check(release:"MDK10.0", reference:"perl-5.8.3-5.4.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"perl-base-5.8.3-5.4.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"perl-devel-5.8.3-5.4.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"perl-doc-5.8.3-5.4.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.1", reference:"perl-5.8.5-3.4.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"perl-base-5.8.5-3.4.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"perl-devel-5.8.5-3.4.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"perl-doc-5.8.5-3.4.101mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.2", reference:"perl-5.8.6-6.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"perl-base-5.8.6-6.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"perl-devel-5.8.6-6.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"perl-doc-5.8.6-6.1.102mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
