#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2009:061. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(37354);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/11/28 21:39:23 $");

  script_cve_id("CVE-2008-4242", "CVE-2009-0542", "CVE-2009-0543");
  script_bugtraq_id(31289, 33722);
  script_xref(name:"MDVSA", value:"2009:061");

  script_name(english:"Mandriva Linux Security Advisory : proftpd (MDVSA-2009:061)");
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
"multiple vulnerabilities has been identified and fixed in proftpd :

ProFTPD 1.3.1 interprets long commands from an FTP client as multiple
commands, which allows remote attackers to conduct cross-site request
forgery (CSRF) attacks and execute arbitrary FTP commands via a long
ftp:// URI that leverages an existing session from the FTP client
implementation in a web browser. (CVE-2008-4242)

SQL injection vulnerability in ProFTPD Server 1.3.1 through 1.3.2rc2
allows remote attackers to execute arbitrary SQL commands via a '%'
(percent) character in the username, which introduces a ''' (single
quote) character during variable substitution by mod_sql.
(CVE-2009-0542)

ProFTPD Server 1.3.1, with NLS support enabled, allows remote
attackers to bypass SQL injection protection mechanisms via invalid,
encoded multibyte characters, which are not properly handled in (1)
mod_sql_mysql and (2) mod_sql_postgres. (CVE-2009-0543)

The updated packages have been upgraded to the latest proftpd version
(1.3.2) to prevent this."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(89, 352);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_autohost");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_ban");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_case");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_ctrls_admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_gss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_ifsession");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_load");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_quotatab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_quotatab_file");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_quotatab_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_quotatab_radius");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_quotatab_sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_radius");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_ratio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_rewrite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_shaper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_site_misc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_sql_mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_sql_postgres");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_time");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_tls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_vroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_wrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_wrap_file");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_wrap_sql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/27");
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
if (rpm_check(release:"MDK2008.0", reference:"proftpd-1.3.2-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-devel-1.3.2-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_autohost-1.3.2-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_ban-1.3.2-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_case-1.3.2-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_ctrls_admin-1.3.2-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_gss-1.3.2-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_ifsession-1.3.2-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_ldap-1.3.2-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_load-1.3.2-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_quotatab-1.3.2-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_quotatab_file-1.3.2-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_quotatab_ldap-1.3.2-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_quotatab_radius-1.3.2-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_quotatab_sql-1.3.2-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_radius-1.3.2-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_ratio-1.3.2-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_rewrite-1.3.2-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_shaper-1.3.2-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_site_misc-1.3.2-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_sql-1.3.2-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_sql_mysql-1.3.2-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_sql_postgres-1.3.2-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_time-1.3.2-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_tls-1.3.2-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_wrap-1.3.2-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_wrap_file-1.3.2-0.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_wrap_sql-1.3.2-0.1mdv2008.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2008.1", reference:"proftpd-1.3.2-0.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"proftpd-devel-1.3.2-0.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"proftpd-mod_autohost-1.3.2-0.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"proftpd-mod_ban-1.3.2-0.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"proftpd-mod_case-1.3.2-0.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"proftpd-mod_ctrls_admin-1.3.2-0.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"proftpd-mod_gss-1.3.2-0.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"proftpd-mod_ifsession-1.3.2-0.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"proftpd-mod_ldap-1.3.2-0.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"proftpd-mod_load-1.3.2-0.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"proftpd-mod_quotatab-1.3.2-0.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"proftpd-mod_quotatab_file-1.3.2-0.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"proftpd-mod_quotatab_ldap-1.3.2-0.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"proftpd-mod_quotatab_radius-1.3.2-0.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"proftpd-mod_quotatab_sql-1.3.2-0.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"proftpd-mod_radius-1.3.2-0.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"proftpd-mod_ratio-1.3.2-0.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"proftpd-mod_rewrite-1.3.2-0.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"proftpd-mod_shaper-1.3.2-0.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"proftpd-mod_site_misc-1.3.2-0.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"proftpd-mod_sql-1.3.2-0.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"proftpd-mod_sql_mysql-1.3.2-0.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"proftpd-mod_sql_postgres-1.3.2-0.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"proftpd-mod_time-1.3.2-0.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"proftpd-mod_tls-1.3.2-0.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"proftpd-mod_wrap-1.3.2-0.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"proftpd-mod_wrap_file-1.3.2-0.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"proftpd-mod_wrap_sql-1.3.2-0.1mdv2008.1", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2009.0", reference:"proftpd-1.3.2-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"proftpd-devel-1.3.2-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"proftpd-mod_autohost-1.3.2-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"proftpd-mod_ban-1.3.2-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"proftpd-mod_case-1.3.2-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"proftpd-mod_ctrls_admin-1.3.2-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"proftpd-mod_gss-1.3.2-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"proftpd-mod_ifsession-1.3.2-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"proftpd-mod_ldap-1.3.2-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"proftpd-mod_load-1.3.2-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"proftpd-mod_quotatab-1.3.2-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"proftpd-mod_quotatab_file-1.3.2-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"proftpd-mod_quotatab_ldap-1.3.2-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"proftpd-mod_quotatab_radius-1.3.2-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"proftpd-mod_quotatab_sql-1.3.2-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"proftpd-mod_radius-1.3.2-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"proftpd-mod_ratio-1.3.2-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"proftpd-mod_rewrite-1.3.2-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"proftpd-mod_shaper-1.3.2-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"proftpd-mod_site_misc-1.3.2-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"proftpd-mod_sql-1.3.2-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"proftpd-mod_sql_mysql-1.3.2-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"proftpd-mod_sql_postgres-1.3.2-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"proftpd-mod_time-1.3.2-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"proftpd-mod_tls-1.3.2-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"proftpd-mod_vroot-1.3.2-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"proftpd-mod_wrap-1.3.2-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"proftpd-mod_wrap_file-1.3.2-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"proftpd-mod_wrap_sql-1.3.2-0.1mdv2009.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
