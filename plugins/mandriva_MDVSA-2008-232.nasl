#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2008:232. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(38066);
  script_version ("$Revision: 1.10 $");
  script_cvs_date("$Date: 2013/06/01 00:06:02 $");

  script_cve_id("CVE-2008-4577", "CVE-2008-4578");
  script_xref(name:"MDVSA", value:"2008:232");

  script_name(english:"Mandriva Linux Security Advisory : dovecot (MDVSA-2008:232)");
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
"The ACL plugin in dovecot prior to version 1.1.4 treated negative
access rights as though they were positive access rights, which
allowed attackers to bypass intended access restrictions
(CVE-2008-4577).

The ACL plugin in dovecot prior to version 1.1.4 allowed attackers to
bypass intended access restrictions by using the 'k' right to create
unauthorized 'parent/child/child' mailboxes (CVE-2008-4578).

In addition, two bugs were discovered in the dovecot package shipped
with Mandriva Linux 2009.0. The default permissions on the
dovecot.conf configuration file were too restrictive, which prevents
the use of dovecot's 'deliver' command as a non-root user. Secondly,
dovecot should not start until after ntpd, if ntpd is active, because
if ntpd corrects the time backwards while dovecot is running, dovecot
will quit automatically, with the log message 'Time just moved
backwards by X seconds. This might cause a lot of problems, so I'll
just kill myself now.' The update resolves both these problems. The
default permissions on dovecot.conf now allow the 'deliver' command to
read the file. Note that if you edited dovecot.conf at all prior to
installing the update, the new permissions may not be applied. If you
find the 'deliver' command still does not work following the update,
please run these commands as root :

# chmod 0640 /etc/dovecot.conf # chown root:mail /etc/dovecot.conf

Dovecot's initialization script now configures it to start after the
ntpd service, to ensure ntpd resetting the clock does not interfere
with Dovecot operation.

This package corrects the above-noted bugs and security issues by
upgrading to the latest dovecot 1.1.6, which also provides additional
bug fixes."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://qa.mandriva.com/44926"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dovecot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dovecot-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dovecot-plugins-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dovecot-plugins-ldap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2009.0", reference:"dovecot-1.1.6-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"dovecot-devel-1.1.6-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"dovecot-plugins-gssapi-1.1.6-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"dovecot-plugins-ldap-1.1.6-0.1mdv2009.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
