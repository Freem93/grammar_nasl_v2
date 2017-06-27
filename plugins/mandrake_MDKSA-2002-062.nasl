#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2002:062. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(13963);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2013/05/31 23:43:26 $");

  script_cve_id("CVE-2002-0972", "CVE-2002-1397", "CVE-2002-1398", "CVE-2002-1400", "CVE-2002-1401", "CVE-2002-1402");
  script_xref(name:"MDKSA", value:"2002:062-1");

  script_name(english:"Mandrake Linux Security Advisory : postgresql (MDKSA-2002:062-1)");
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
"Vulnerabilities were discovered in the Postgresql relational database
by Mordred Labs. These vulnerabilities are buffer overflows in the
rpad(), lpad(), repeat(), and cash_words() functions. The Postgresql
developers also fixed a buffer overflow in functions that deal with
time/date and timezone.

Finally, more buffer overflows were discovered by Mordred Labs in the
7.2.2 release that are currently only fixed in CVS. These buffer
overflows exist in the circle_poly(), path_encode(), and path_addr()
functions.

In order for these vulnerabilities to be exploited, an attacker must
be able to query the server somehow. However, this cannot directly
lead to root privilege because the server runs as the postgresql user.

Prior to upgrading, users should dump their database and retain it as
backup. You can dump the database by using :

$ pg_dumpall > db.out

If you need to restore from the backup, you can do so by using :

$ psql -f db.out template1

Update :

The previous update missed a few small fixes, including a buffer
overflow in the cash_words() function that allows local users to cause
a DoS and possibly execute arbitrary code via a malformed argument in
Postgresql 7.2 and earlier. As well, buffer overflows in the TZ and
SET TIME ZONE environment variables for Postgresql 7.2.1 and earlier
can allow local users to cause a DoS and possibly execute arbitrary
code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://archives.postgresql.org/pgsql-announce/2002-08/msg00004.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://online.securityfocus.com/archive/1/288036"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://online.securityfocus.com/archive/1/288305"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://online.securityfocus.com/archive/1/288334"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libecpg3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpgperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpgsql2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpgsqlodbc0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpgtcl2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql-tk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:7.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/02/11");
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
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"postgresql-7.0.2-6.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"postgresql-devel-7.0.2-6.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"postgresql-jdbc-7.0.2-6.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"postgresql-odbc-7.0.2-6.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"postgresql-perl-7.0.2-6.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"postgresql-python-7.0.2-6.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"postgresql-server-7.0.2-6.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"postgresql-tcl-7.0.2-6.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"postgresql-test-7.0.2-6.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"postgresql-tk-7.0.2-6.2mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"postgresql-7.0.3-12.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"postgresql-devel-7.0.3-12.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"postgresql-jdbc-7.0.3-12.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"postgresql-odbc-7.0.3-12.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"postgresql-perl-7.0.3-12.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"postgresql-python-7.0.3-12.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"postgresql-server-7.0.3-12.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"postgresql-tcl-7.0.3-12.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"postgresql-test-7.0.3-12.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"postgresql-tk-7.0.3-12.3mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"postgresql-7.1.2-19.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"postgresql-contrib-7.1.2-19.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"postgresql-devel-7.1.2-19.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"postgresql-docs-7.1.2-19.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"postgresql-jdbc-7.1.2-19.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"postgresql-libs-7.1.2-19.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"postgresql-odbc-7.1.2-19.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"postgresql-perl-7.1.2-19.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"postgresql-plperl-7.1.2-19.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"postgresql-python-7.1.2-19.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"postgresql-server-7.1.2-19.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"postgresql-tcl-7.1.2-19.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"postgresql-test-7.1.2-19.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"postgresql-tk-7.1.2-19.3mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"libecpg3-7.2-12.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"libpgperl-7.2-12.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"libpgsql2-7.2-12.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"libpgsqlodbc0-7.2-12.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"libpgtcl2-7.2-12.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"postgresql-7.2-12.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"postgresql-contrib-7.2-12.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"postgresql-devel-7.2-12.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"postgresql-docs-7.2-12.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"postgresql-jdbc-7.2-12.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"postgresql-python-7.2-12.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"postgresql-server-7.2-12.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"postgresql-tcl-7.2-12.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"postgresql-test-7.2-12.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"postgresql-tk-7.2-12.2mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"libecpg3-7.2.2-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"libpgperl-7.2.2-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"libpgsql2-7.2.2-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"libpgsqlodbc0-7.2.2-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"libpgtcl2-7.2.2-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"postgresql-7.2.2-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"postgresql-contrib-7.2.2-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"postgresql-devel-7.2.2-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"postgresql-docs-7.2.2-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"postgresql-jdbc-7.2.2-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"postgresql-python-7.2.2-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"postgresql-server-7.2.2-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"postgresql-tcl-7.2.2-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"postgresql-test-7.2.2-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"postgresql-tk-7.2.2-1.2mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
