#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2015:113. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(82366);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/03/30 13:59:00 $");

  script_cve_id("CVE-2014-3430");
  script_xref(name:"MDVSA", value:"2015:113");

  script_name(english:"Mandriva Linux Security Advisory : dovecot (MDVSA-2015:113)");
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
"Updated dovecot packages fix security vulnerability.

Dovecot before 2.2.13 is vulnerable to a DoS attack against
imap/pop3-login processes. If SSL/TLS handshake was started but wasn't
finished, the login process attempted to eventually forcibly
disconnect the client, but failed to do it correctly. This could have
left the connections hanging around for a long time (CVE-2014-3430)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0223.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dovecot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dovecot-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dovecot-pigeonhole");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dovecot-pigeonhole-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dovecot-plugins-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dovecot-plugins-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dovecot-plugins-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dovecot-plugins-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dovecot-plugins-sqlite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"dovecot-2.2.6-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"dovecot-devel-2.2.6-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"dovecot-pigeonhole-2.2.6-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"dovecot-pigeonhole-devel-2.2.6-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"dovecot-plugins-gssapi-2.2.6-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"dovecot-plugins-ldap-2.2.6-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"dovecot-plugins-mysql-2.2.6-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"dovecot-plugins-pgsql-2.2.6-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"dovecot-plugins-sqlite-2.2.6-3.1.mbs2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
