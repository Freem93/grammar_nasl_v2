# @DEPRECATED@
#
# This script has been deprecated as the associated patch is not
# currently a security fix.
#
# Disabled on 2012/09/06.
#

#
# (C) Tenable Network Security, Inc.
#
# This script was automatically generated from
# Mandrake Linux Security Advisory MDKA-2007:089.
#

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(26005);
  script_version ("$Revision: 1.9 $"); 
  script_cvs_date("$Date: 2012/09/07 00:24:00 $");

  script_name(english:"MDKA-2007:089 : proftpd");
  script_summary(english:"Checks for patch(es) in 'rpm -qa' output");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Mandrake host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"A bug in ProFTPD, when run on an IPv6-capable host, causes ProFTPD to
generate an excessive number of error messages to syslog. As well,
LDAP TLS support was incorrectly setup during compilation and as a
result LDAP TLS support was disabled.

The updated packages correct these issues.");
  script_set_attribute(attribute:"see_also", value:"http://www.mandriva.com/security/advisories?name=MDKA-2007:089");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/06");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux");
  script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/09/07");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Mandriva Local Security Checks");
 
  script_copyright(english:"This script is Copyright (C) 2007-2011 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}

# Deprecated.
exit(0, "The associated patch is not currently a security fix.");


include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/Mandrake/release")) exit(0, "The host is not running Mandrake Linux.");
if (!get_kb_item("Host/Mandrake/rpm-list")) exit(1, "Could not get the list of packages.");

flag = 0;

if (rpm_check(reference:"proftpd-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-anonymous-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_autohost-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_case-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_clamav-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_ctrls_admin-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_facl-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_gss-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_ifsession-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_ldap-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_load-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_quotatab-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_quotatab_file-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_quotatab_ldap-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_quotatab_sql-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_radius-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_ratio-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_rewrite-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_shaper-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_site_misc-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_sql-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_sql_mysql-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_sql_postgres-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_time-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_tls-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_wrap-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_wrap_file-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_wrap_sql-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"i386", yank:"mdv")) flag++;

if (rpm_check(reference:"proftpd-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-anonymous-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_autohost-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_case-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_clamav-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_ctrls_admin-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_facl-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_gss-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_ifsession-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_ldap-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_load-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_quotatab-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_quotatab_file-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_quotatab_ldap-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_quotatab_sql-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_radius-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_ratio-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_rewrite-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_shaper-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_site_misc-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_sql-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_sql_mysql-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_sql_postgres-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_time-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_tls-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_wrap-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_wrap_file-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_wrap_sql-1.3.0-4.6mdv2007.0", release:"MDK2007.0", cpu:"x86_64", yank:"mdv")) flag++;

if (rpm_check(reference:"proftpd-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-devel-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_autohost-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_ban-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_case-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_clamav-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_ctrls_admin-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_gss-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_ifsession-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_ldap-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_load-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_quotatab-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_quotatab_file-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_quotatab_ldap-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_quotatab_radius-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_quotatab_sql-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_radius-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_ratio-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_rewrite-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_shaper-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_site_misc-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_sql-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_sql_mysql-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_sql_postgres-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_time-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_tls-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_wrap-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_wrap_file-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_wrap_sql-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;

if (rpm_check(reference:"proftpd-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-devel-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_autohost-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_ban-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_case-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_clamav-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_ctrls_admin-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_gss-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_ifsession-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_ldap-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_load-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_quotatab-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_quotatab_file-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_quotatab_ldap-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_quotatab_radius-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_quotatab_sql-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_radius-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_ratio-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_rewrite-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_shaper-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_site_misc-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_sql-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_sql_mysql-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_sql_postgres-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_time-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_tls-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_wrap-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_wrap_file-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"proftpd-mod_wrap_sql-1.3.1-0.rc2.3.3mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else 
{
  exit(0, "The host is not affected.");
}
