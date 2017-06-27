#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2006:217. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(24602);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/31 23:56:39 $");

  script_cve_id("CVE-2006-5815", "CVE-2006-6170", "CVE-2006-6171");
  script_bugtraq_id(20992);
  script_xref(name:"MDKSA", value:"2006:217-1");

  script_name(english:"Mandrake Linux Security Advisory : proftpd (MDKSA-2006:217-1)");
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
"A stack-based buffer overflow in the sreplace function in ProFTPD
1.3.0 and earlier, allows remote attackers to cause a denial of
service, as demonstrated by vd_proftpd.pm, a 'ProFTPD remote exploit.'
(CVE-2006-5815)

Buffer overflow in the tls_x509_name_oneline function in the mod_tls
module, as used in ProFTPD 1.3.0a and earlier, and possibly other
products, allows remote attackers to execute arbitrary code via a
large data length argument, a different vulnerability than
CVE-2006-5815. (CVE-2006-6170)

ProFTPD 1.3.0a and earlier does not properly set the buffer size limit
when CommandBufferSize is specified in the configuration file, which
leads to an off-by-two buffer underflow. NOTE: in November 2006, the
role of CommandBufferSize was originally associated with
CVE-2006-5815, but this was an error stemming from an initial vague
disclosure. NOTE: ProFTPD developers dispute this issue, saying that
the relevant memory location is overwritten by assignment before
further use within the affected function, so this is not a
vulnerability. (CVE-2006-6171)

Packages have been patched to correct these issues.

Update :

The previous update incorrectly linked the vd_proftd.pm issue with the
CommandBufferSize issue. These are two distinct issues and the
previous update only addressed CommandBufferSize (CVE-2006-6171), and
the mod_tls issue (CVE-2006-6170)."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'ProFTPD 1.2 - 1.3.0 sreplace Buffer Overflow (Linux)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-anonymous");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_autohost");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_case");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_clamav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_ctrls_admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_facl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_gss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_ifsession");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_load");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_quotatab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_quotatab_file");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_quotatab_ldap");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_wrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_wrap_file");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_wrap_sql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2006.0", reference:"proftpd-1.2.10-13.3.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"proftpd-anonymous-1.2.10-13.3.20060mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK2007.0", reference:"proftpd-1.3.0-4.3mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"proftpd-anonymous-1.3.0-4.3mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"proftpd-mod_autohost-1.3.0-4.3mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"proftpd-mod_case-1.3.0-4.3mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"proftpd-mod_clamav-1.3.0-4.3mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"proftpd-mod_ctrls_admin-1.3.0-4.3mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"proftpd-mod_facl-1.3.0-4.3mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"proftpd-mod_gss-1.3.0-4.3mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"proftpd-mod_ifsession-1.3.0-4.3mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"proftpd-mod_ldap-1.3.0-4.3mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"proftpd-mod_load-1.3.0-4.3mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"proftpd-mod_quotatab-1.3.0-4.3mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"proftpd-mod_quotatab_file-1.3.0-4.3mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"proftpd-mod_quotatab_ldap-1.3.0-4.3mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"proftpd-mod_quotatab_sql-1.3.0-4.3mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"proftpd-mod_radius-1.3.0-4.3mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"proftpd-mod_ratio-1.3.0-4.3mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"proftpd-mod_rewrite-1.3.0-4.3mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"proftpd-mod_shaper-1.3.0-4.3mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"proftpd-mod_site_misc-1.3.0-4.3mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"proftpd-mod_sql-1.3.0-4.3mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"proftpd-mod_sql_mysql-1.3.0-4.3mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"proftpd-mod_sql_postgres-1.3.0-4.3mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"proftpd-mod_time-1.3.0-4.3mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"proftpd-mod_tls-1.3.0-4.3mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"proftpd-mod_wrap-1.3.0-4.3mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"proftpd-mod_wrap_file-1.3.0-4.3mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"proftpd-mod_wrap_sql-1.3.0-4.3mdv2007.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
