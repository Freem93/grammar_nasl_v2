#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2009:131. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(39323);
  script_version ("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/11/28 21:39:23 $");

  script_cve_id("CVE-2009-0023", "CVE-2009-1955", "CVE-2009-1956");
  script_bugtraq_id(35221);
  script_xref(name:"MDVSA", value:"2009:131");

  script_name(english:"Mandriva Linux Security Advisory : apr-util (MDVSA-2009:131)");
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
"Multiple security vulnerabilities has been identified and fixed in
apr-util :

The apr_strmatch_precompile function in strmatch/apr_strmatch.c in
Apache APR-util before 1.3.5 allows remote attackers to cause a denial
of service (daemon crash) via crafted input involving (1) a .htaccess
file used with the Apache HTTP Server, (2) the SVNMasterURI directive
in the mod_dav_svn module in the Apache HTTP Server, (3) the
mod_apreq2 module for the Apache HTTP Server, or (4) an application
that uses the libapreq2 library, related to an underflow flaw.
(CVE-2009-0023).

The expat XML parser in the apr_xml_* interface in xml/apr_xml.c in
Apache APR-util before 1.3.7, as used in the mod_dav and mod_dav_svn
modules in the Apache HTTP Server, allows remote attackers to cause a
denial of service (memory consumption) via a crafted XML document
containing a large number of nested entity references, as demonstrated
by a PROPFIND request, a similar issue to CVE-2003-1564
(CVE-2009-1955).

Off-by-one error in the apr_brigade_vprintf function in Apache
APR-util before 1.3.5 on big-endian platforms allows remote attackers
to obtain sensitive information or cause a denial of service
(application crash) via crafted input (CVE-2009-1956).

The updated packages have been patched to prevent this."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apr-util-dbd-freetds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apr-util-dbd-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apr-util-dbd-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apr-util-dbd-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apr-util-dbd-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apr-util-dbd-sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64apr-util-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64apr-util1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libapr-util-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libapr-util1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/08");
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
if (rpm_check(release:"MDK2008.1", reference:"apr-util-dbd-mysql-1.2.12-4.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"apr-util-dbd-pgsql-1.2.12-4.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"apr-util-dbd-sqlite3-1.2.12-4.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"x86_64", reference:"lib64apr-util-devel-1.2.12-4.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"x86_64", reference:"lib64apr-util1-1.2.12-4.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"libapr-util-devel-1.2.12-4.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"libapr-util1-1.2.12-4.1mdv2008.1", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2009.0", reference:"apr-util-dbd-freetds-1.3.4-2.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"apr-util-dbd-ldap-1.3.4-2.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"apr-util-dbd-mysql-1.3.4-2.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"apr-util-dbd-odbc-1.3.4-2.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"apr-util-dbd-pgsql-1.3.4-2.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"apr-util-dbd-sqlite3-1.3.4-2.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64apr-util-devel-1.3.4-2.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64apr-util1-1.3.4-2.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libapr-util-devel-1.3.4-2.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libapr-util1-1.3.4-2.1mdv2009.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2009.1", reference:"apr-util-dbd-freetds-1.3.4-9.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"apr-util-dbd-ldap-1.3.4-9.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"apr-util-dbd-mysql-1.3.4-9.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"apr-util-dbd-odbc-1.3.4-9.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"apr-util-dbd-pgsql-1.3.4-9.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"apr-util-dbd-sqlite3-1.3.4-9.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64apr-util-devel-1.3.4-9.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64apr-util1-1.3.4-9.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libapr-util-devel-1.3.4-9.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libapr-util1-1.3.4-9.1mdv2009.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
