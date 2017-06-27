#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:225. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(20456);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/03/19 14:42:14 $");

  script_cve_id("CVE-2005-3962");
  script_bugtraq_id(15629);
  script_xref(name:"MDKSA", value:"2005:225");

  script_name(english:"Mandrake Linux Security Advisory : perl (MDKSA-2005:225)");
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
"Jack Louis discovered a new way to exploit format string errors in the
Perl programming language that could lead to the execution of
arbitrary code.

The updated packages are patched to close the particular exploit
vector in Perl itself, to mitigate the risk of format string
programming errors, however it does not fix problems that may exist in
particular pieces of software written in Perl."
  );
  # http://www.dyadsecurity.com/perl-0002.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a844180b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:perl-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:perl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:perl-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:perl-suid");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:mandrakesoft:mandrake_linux:le2005");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK10.1", reference:"perl-5.8.5-3.5.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"perl-base-5.8.5-3.5.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"perl-devel-5.8.5-3.5.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"perl-doc-5.8.5-3.5.101mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.2", reference:"perl-5.8.6-6.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"perl-base-5.8.6-6.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"perl-devel-5.8.6-6.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"perl-doc-5.8.6-6.2.102mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK2006.0", reference:"perl-5.8.7-3.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"perl-base-5.8.7-3.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"perl-devel-5.8.7-3.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"perl-doc-5.8.7-3.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"perl-suid-5.8.7-3.2.20060mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
