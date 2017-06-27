#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:040. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(17139);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/11/28 21:39:21 $");

  script_cve_id("CVE-2005-0227", "CVE-2005-0244", "CVE-2005-0245", "CVE-2005-0246", "CVE-2005-0247");
  script_xref(name:"MDKSA", value:"2005:040");

  script_name(english:"Mandrake Linux Security Advisory : postgresql (MDKSA-2005:040)");
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
"A number of vulnerabilities were found and corrected in the PostgreSQL
DBMS :

A flaw in the LOAD command could be abused by a local user to load
arbitrary shared libraries and as a result execute arbitrary code with
the privileges of the user running the postgresql server
(CVE-2005-0227).

A permission checking flaw was found where a local user could bypass
the EXECUTE permission check for functions using the CREATE AGGREGATE
command (CVE-2005-0244).

Multiple buffer overflows were discovered in PL/PgSQL. A database user
with permission to create plpgsql functions could trigger these flaws
which could then lead to arbitrary code execution with the privileges
of the user running the postgresql server (CVE-2005-0245 and
CVE-2005-0247).

Finally, a flaw in the integer aggregator (intagg) contrib module was
found. A user could create carefully crafted arrays and crash the
server, causing a Denial of Service (CVE-2005-0246).

The updated packages have been patched to correct these problems."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(94, 119, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ecpg3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ecpg3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64pgtcl2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64pgtcl2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64pq3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64pq3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libecpg3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libecpg3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpgtcl2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpgtcl2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpq3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpq3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64ecpg3-7.4.1-2.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64ecpg3-devel-7.4.1-2.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64pgtcl2-7.4.1-2.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64pgtcl2-devel-7.4.1-2.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64pq3-7.4.1-2.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64pq3-devel-7.4.1-2.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libecpg3-7.4.1-2.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libecpg3-devel-7.4.1-2.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libpgtcl2-7.4.1-2.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libpgtcl2-devel-7.4.1-2.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libpq3-7.4.1-2.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libpq3-devel-7.4.1-2.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"postgresql-7.4.1-2.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"postgresql-contrib-7.4.1-2.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"postgresql-devel-7.4.1-2.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"postgresql-docs-7.4.1-2.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"postgresql-jdbc-7.4.1-2.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"postgresql-pl-7.4.1-2.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"postgresql-server-7.4.1-2.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"postgresql-tcl-7.4.1-2.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"postgresql-test-7.4.1-2.3.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64ecpg3-7.4.5-4.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64ecpg3-devel-7.4.5-4.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64pgtcl2-7.4.5-4.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64pgtcl2-devel-7.4.5-4.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64pq3-7.4.5-4.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64pq3-devel-7.4.5-4.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libecpg3-7.4.5-4.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libecpg3-devel-7.4.5-4.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libpgtcl2-7.4.5-4.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libpgtcl2-devel-7.4.5-4.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libpq3-7.4.5-4.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libpq3-devel-7.4.5-4.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"postgresql-7.4.5-4.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"postgresql-contrib-7.4.5-4.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"postgresql-devel-7.4.5-4.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"postgresql-docs-7.4.5-4.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"postgresql-jdbc-7.4.5-4.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"postgresql-pl-7.4.5-4.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"postgresql-server-7.4.5-4.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"postgresql-tcl-7.4.5-4.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"postgresql-test-7.4.5-4.2.101mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
