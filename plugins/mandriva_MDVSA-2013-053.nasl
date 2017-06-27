#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:053. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(66067);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/11/25 11:41:40 $");

  script_cve_id("CVE-2012-6095");
  script_bugtraq_id(57172);
  script_xref(name:"MDVSA", value:"2013:053");

  script_name(english:"Mandriva Linux Security Advisory : proftpd (MDVSA-2013:053)");
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
"A vulnerability has been found and corrected in proftpd :

ProFTPD before 1.3.5rc1, when using the UserOwner directive, allows
local users to modify the ownership of arbitrary files via a race
condition and a symlink attack on the (1) MKD or (2) XMKD commands
(CVE-2012-6095).

The updated packages have been patched to correct thies issue."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_sftp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_shaper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_site_misc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_sql_mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_sql_passwd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_sql_postgres");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_time");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_tls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_vroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_wrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_wrap_file");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_wrap_sql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"proftpd-1.3.3g-2.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"proftpd-devel-1.3.3g-2.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"proftpd-mod_autohost-1.3.3g-2.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"proftpd-mod_ban-1.3.3g-2.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"proftpd-mod_case-1.3.3g-2.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"proftpd-mod_ctrls_admin-1.3.3g-2.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"proftpd-mod_gss-1.3.3g-2.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"proftpd-mod_ifsession-1.3.3g-2.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"proftpd-mod_ldap-1.3.3g-2.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"proftpd-mod_load-1.3.3g-2.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"proftpd-mod_quotatab-1.3.3g-2.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"proftpd-mod_quotatab_file-1.3.3g-2.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"proftpd-mod_quotatab_ldap-1.3.3g-2.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"proftpd-mod_quotatab_radius-1.3.3g-2.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"proftpd-mod_quotatab_sql-1.3.3g-2.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"proftpd-mod_radius-1.3.3g-2.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"proftpd-mod_ratio-1.3.3g-2.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"proftpd-mod_rewrite-1.3.3g-2.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"proftpd-mod_sftp-1.3.3g-2.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"proftpd-mod_shaper-1.3.3g-2.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"proftpd-mod_site_misc-1.3.3g-2.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"proftpd-mod_sql-1.3.3g-2.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"proftpd-mod_sql_mysql-1.3.3g-2.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"proftpd-mod_sql_passwd-1.3.3g-2.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"proftpd-mod_sql_postgres-1.3.3g-2.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"proftpd-mod_time-1.3.3g-2.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"proftpd-mod_tls-1.3.3g-2.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"proftpd-mod_vroot-1.3.3g-2.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"proftpd-mod_wrap-1.3.3g-2.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"proftpd-mod_wrap_file-1.3.3g-2.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"proftpd-mod_wrap_sql-1.3.3g-2.1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
