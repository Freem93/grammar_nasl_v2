#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2006:098. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(21670);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/05/31 23:56:38 $");

  script_cve_id("CVE-2006-2313", "CVE-2006-2314");
  script_xref(name:"MDKSA", value:"2006:098");

  script_name(english:"Mandrake Linux Security Advisory : postgresql (MDKSA-2006:098)");
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
"PostgreSQL 8.1.x before 8.1.4, 8.0.x before 8.0.8, 7.4.x before
7.4.13, 7.3.x before 7.3.15, and earlier versions allows
context-dependent attackers to bypass SQL injection protection methods
in applications via invalid encodings of multibyte characters, aka one
variant of 'Encoding-Based SQL Injection.' (CVE-2006-2313)

PostgreSQL 8.1.x before 8.1.4, 8.0.x before 8.0.8, 7.4.x before
7.4.13, 7.3.x before 7.3.15, and earlier versions allows
context-dependent attackers to bypass SQL injection protection methods
in applications that use multibyte encodings that allow the ''
(backslash) byte 0x5c to be the trailing byte of a multibyte
character, such as SJIS, BIG5, GBK, GB18030, and UHC, which cannot be
handled correctly by a client that does not understand multibyte
encodings, aka a second variant of 'Encoding-Based SQL Injection.'
NOTE: it could be argued that this is a class of issue related to
interaction errors between the client and PostgreSQL, but a CVE has
been assigned since PostgreSQL is treating this as a preventative
measure against this class of problem. (CVE-2006-2314)

Packages have been patched or updated to correct these issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ecpg5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ecpg5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64pq4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64pq4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libecpg5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libecpg5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpq4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpq4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql-plpgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:mandrakesoft:mandrake_linux:le2005");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/06/08");
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
if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64ecpg5-8.0.8-0.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64ecpg5-devel-8.0.8-0.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64pq4-8.0.8-0.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64pq4-devel-8.0.8-0.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libecpg5-8.0.8-0.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libecpg5-devel-8.0.8-0.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libpq4-8.0.8-0.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libpq4-devel-8.0.8-0.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"postgresql-8.0.8-0.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"postgresql-contrib-8.0.8-0.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"postgresql-devel-8.0.8-0.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"postgresql-docs-8.0.8-0.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"postgresql-jdbc-8.0.8-0.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"postgresql-pl-8.0.8-0.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"postgresql-plperl-8.0.8-0.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"postgresql-plpgsql-8.0.8-0.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"postgresql-plpython-8.0.8-0.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"postgresql-pltcl-8.0.8-0.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"postgresql-server-8.0.8-0.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"postgresql-test-8.0.8-0.1.102mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64ecpg5-8.0.8-0.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64ecpg5-devel-8.0.8-0.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64pq4-8.0.8-0.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64pq4-devel-8.0.8-0.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libecpg5-8.0.8-0.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libecpg5-devel-8.0.8-0.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libpq4-8.0.8-0.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libpq4-devel-8.0.8-0.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"postgresql-8.0.8-0.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"postgresql-contrib-8.0.8-0.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"postgresql-devel-8.0.8-0.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"postgresql-docs-8.0.8-0.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"postgresql-jdbc-8.0.8-0.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"postgresql-pl-8.0.8-0.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"postgresql-plperl-8.0.8-0.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"postgresql-plpgsql-8.0.8-0.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"postgresql-plpython-8.0.8-0.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"postgresql-pltcl-8.0.8-0.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"postgresql-server-8.0.8-0.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"postgresql-test-8.0.8-0.1.20060mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
