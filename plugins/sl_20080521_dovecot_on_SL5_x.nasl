#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60404);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:22:13 $");

  script_cve_id("CVE-2007-2231", "CVE-2007-4211", "CVE-2007-6598", "CVE-2008-1199");

  script_name(english:"Scientific Linux Security Update : dovecot on SL5.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Scientific Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A flaw was discovered in the way Dovecot handled the
'mail_extra_groups' option. An authenticated attacker with local shell
access could leverage this flaw to read, modify, or delete other users
mail that is stored on the mail server. (CVE-2008-1199)

This issue did not affect the default Red Hat Enterprise Linux 5
Dovecot configuration. This update adds two new configuration options
-- 'mail_privileged_group' and 'mail_access_groups' -- to minimize the
usage of additional privileges.

A directory traversal flaw was discovered in Dovecot's zlib plug-in.
An authenticated user could use this flaw to view other compressed
mailboxes with the permissions of the Dovecot process. (CVE-2007-2231)

A flaw was found in the Dovecot ACL plug-in. User with only insert
permissions for a mailbox could use the 'COPY' and 'APPEND' commands
to set additional message flags. (CVE-2007-4211)

A flaw was found in a way Dovecot cached LDAP query results in certain
configurations. This could possibly allow authenticated users to log
in as a different user who has the same password. (CVE-2007-6598)

As well, this updated package fixes the following bugs :

  - configuring 'userdb' and 'passdb' to use LDAP caused
    Dovecot to hang. A segmentation fault may have occurred.
    In this updated package, using an LDAP backend for
    'userdb' and 'passdb' no longer causes Dovecot to hang.

  - the Dovecot 'login_process_size' limit was configured
    for 32-bit systems. On 64-bit systems, when Dovecot was
    configured to use either IMAP or POP3, the log in
    processes crashed with out-of-memory errors. Errors such
    as the following were logged :

pop3-login: pop3-login: error while loading shared libraries:
libsepol.so.1: failed to map segment from shared object: Cannot
allocate memory

In this updated package, the 'login_process_size' limit is correctly
configured on 64-bit systems, which resolves this issue.

Note: this updated package upgrades dovecot to version 1.0.7. For
further details, refer to the Dovecot changelog:
http://koji.fedoraproject.org/koji/buildinfo?buildID=23397"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://koji.fedoraproject.org/koji/buildinfo?buildID=23397"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0805&L=scientific-linux-errata&T=0&P=1937
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7f6d46fb"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dovecot package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(16, 59, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"dovecot-1.0.7-2.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
