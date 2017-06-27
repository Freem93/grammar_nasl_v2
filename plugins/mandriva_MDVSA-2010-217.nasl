#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2010:217. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(50425);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2013/06/01 00:15:50 $");

  script_cve_id("CVE-2010-3304", "CVE-2010-3706", "CVE-2010-3707", "CVE-2010-3779", "CVE-2010-3780");
  script_bugtraq_id(41964, 43690);
  script_xref(name:"MDVSA", value:"2010:217");

  script_name(english:"Mandriva Linux Security Advisory : dovecot (MDVSA-2010:217)");
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
"Multiple vulnerabilities was discovered and corrected in dovecot :

Dovecot 1.2.x before 1.2.15 and 2.0.x before 2.0.beta2 grants the
admin permission to the owner of each mailbox in a non-public
namespace, which might allow remote authenticated users to bypass
intended access restrictions by changing the ACL of a mailbox, as
demonstrated by a symlinked shared mailbox (CVE-2010-3779).

Dovecot 1.2.x before 1.2.15 allows remote authenticated users to cause
a denial of service (master process outage) by simultaneously
disconnecting many (1) IMAP or (2) POP3 sessions (CVE-2010-3780).

The ACL plugin in Dovecot 1.2.x before 1.2.13 propagates INBOX ACLs to
newly created mailboxes in certain configurations, which might allow
remote attackers to read mailboxes that have unintended weak ACLs
(CVE-2010-3304).

plugins/acl/acl-backend-vfile.c in Dovecot 1.2.x before 1.2.15 and
2.0.x before 2.0.5 interprets an ACL entry as a directive to add to
the permissions granted by another ACL entry, instead of a directive
to replace the permissions granted by another ACL entry, in certain
circumstances involving the private namespace of a user, which allows
remote authenticated users to bypass intended access restrictions via
a request to read or modify a mailbox (CVE-2010-3706).

plugins/acl/acl-backend-vfile.c in Dovecot 1.2.x before 1.2.15 and
2.0.x before 2.0.5 interprets an ACL entry as a directive to add to
the permissions granted by another ACL entry, instead of a directive
to replace the permissions granted by another ACL entry, in certain
circumstances involving more specific entries that occur after less
specific entries, which allows remote authenticated users to bypass
intended access restrictions via a request to read or modify a mailbox
(CVE-2010-3707).

This advisory provides dovecot 1.2.15 which is not vulnerable to these
issues"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/01");
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
if (rpm_check(release:"MDK2010.0", reference:"dovecot-1.2.15-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"dovecot-devel-1.2.15-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"dovecot-plugins-gssapi-1.2.15-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"dovecot-plugins-ldap-1.2.15-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"dovecot-plugins-managesieve-1.2.15-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"dovecot-plugins-mysql-1.2.15-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"dovecot-plugins-pgsql-1.2.15-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"dovecot-plugins-sieve-1.2.15-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"dovecot-plugins-sqlite-1.2.15-0.1mdv2010.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2010.1", reference:"dovecot-1.2.15-0.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"dovecot-devel-1.2.15-0.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"dovecot-plugins-gssapi-1.2.15-0.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"dovecot-plugins-ldap-1.2.15-0.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"dovecot-plugins-managesieve-1.2.15-0.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"dovecot-plugins-mysql-1.2.15-0.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"dovecot-plugins-pgsql-1.2.15-0.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"dovecot-plugins-sieve-1.2.15-0.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"dovecot-plugins-sqlite-1.2.15-0.1mdv2010.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
