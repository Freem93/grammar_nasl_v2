#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2008:149. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(37407);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/17 17:02:53 $");

  script_cve_id("CVE-2008-2079");
  script_bugtraq_id(29106);
  script_xref(name:"MDVSA", value:"2008:149");

  script_name(english:"Mandriva Linux Security Advisory : mysql (MDVSA-2008:149)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandriva Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Sergei Golubchik found that MySQL did not properly validate optional
data or index directory paths given in a CREATE TABLE statement; as
well it would not, under certain conditions, prevent two databases
from using the same paths for data or index files. This could allow an
authenticated user with appropriate privilege to create tables in one
database to read and manipulate data in tables later created in other
databases, regardless of GRANT privileges (CVE-2008-2079).

The updated packages have been patched to correct this issue."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64mysql-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64mysql15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libmysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libmysql-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libmysql15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mysql-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mysql-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mysql-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mysql-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mysql-max");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mysql-ndb-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mysql-ndb-management");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mysql-ndb-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mysql-ndb-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2008.1", cpu:"x86_64", reference:"lib64mysql-devel-5.0.51a-8.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"x86_64", reference:"lib64mysql-static-devel-5.0.51a-8.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"x86_64", reference:"lib64mysql15-5.0.51a-8.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"libmysql-devel-5.0.51a-8.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"libmysql-static-devel-5.0.51a-8.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"libmysql15-5.0.51a-8.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"mysql-5.0.51a-8.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"mysql-bench-5.0.51a-8.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"mysql-client-5.0.51a-8.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"mysql-common-5.0.51a-8.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"mysql-doc-5.0.51a-8.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"mysql-max-5.0.51a-8.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"mysql-ndb-extra-5.0.51a-8.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"mysql-ndb-management-5.0.51a-8.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"mysql-ndb-storage-5.0.51a-8.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"mysql-ndb-tools-5.0.51a-8.1mdv2008.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
