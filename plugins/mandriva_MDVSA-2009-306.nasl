#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2009:306. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(48160);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2013/06/01 00:11:06 $");

  script_cve_id("CVE-2009-3897");
  script_bugtraq_id(37084);
  script_xref(name:"MDVSA", value:"2009:306");

  script_name(english:"Mandriva Linux Security Advisory : dovecot (MDVSA-2009:306)");
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
"A vulnerability was discovered and corrected in dovecot :

Dovecot 1.2.x before 1.2.8 sets 0777 permissions during creation of
certain directories at installation time, which allows local users to
access arbitrary user accounts by replacing the auth socket, related
to the parent directories of the base_dir directory, and possibly the
base_dir directory itself (CVE-2009-3897).

The updated packages have been patched to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.dovecot.org/list/dovecot-news/2009-November/000143.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dovecot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dovecot-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dovecot-plugins-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dovecot-plugins-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dovecot-plugins-managesieve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dovecot-plugins-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dovecot-plugins-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dovecot-plugins-sieve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dovecot-plugins-sqlite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2010.0", reference:"dovecot-1.2.6-1.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"dovecot-devel-1.2.6-1.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"dovecot-plugins-gssapi-1.2.6-1.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"dovecot-plugins-ldap-1.2.6-1.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"dovecot-plugins-managesieve-1.2.6-1.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"dovecot-plugins-mysql-1.2.6-1.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"dovecot-plugins-pgsql-1.2.6-1.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"dovecot-plugins-sieve-1.2.6-1.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"dovecot-plugins-sqlite-1.2.6-1.1mdv2010.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
