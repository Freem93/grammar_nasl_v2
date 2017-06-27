#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60524);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:53 $");

  script_cve_id("CVE-2008-4577", "CVE-2008-4870");

  script_name(english:"Scientific Linux Security Update : dovecot on SL5.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Scientific Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A flaw was found in Dovecot's ACL plug-in. The ACL plug-in treated
negative access rights as positive rights, which could allow an
attacker to bypass intended access restrictions. (CVE-2008-4577)

A password disclosure flaw was found with Dovecot's configuration
file. If a system had the 'ssl_key_password' option defined, any local
user could view the SSL key password. (CVE-2008-4870)

Note: This flaw did not allow the attacker to acquire the contents of
the SSL key. The password has no value without the key file which
arbitrary users should not have read access to.

To better protect even this value, however, the dovecot.conf file now
supports the '!include_try' directive. The ssl_key_password option
should be moved from dovecot.conf to a new file owned by, and only
readable and writable by, root (ie 0600). This file should be
referenced from dovecot.conf by setting the '!include_try
[/path/to/password/file]' option.

Additionally, this update addresses the following bugs :

  - the dovecot init script -- /etc/rc.d/init.d/dovecot --
    did not check if the dovecot binary or configuration
    files existed. It also used the wrong pid file for
    checking the dovecot service's status. This update
    includes a new init script that corrects these errors.

  - the %files section of the dovecot spec file did not
    include '%dir %{ssldir}/private'. As a consequence, the
    /etc/pki/private/ directory was not owned by dovecot.
    (Note: files inside /etc/pki/private/ were and are owned
    by dovecot.) With this update, the missing line has been
    added to the spec file, and the noted directory is now
    owned by dovecot.

  - in some previously released versions of dovecot, the
    authentication process accepted (and passed along
    un-escaped) passwords containing characters that had
    special meaning to dovecot's internal protocols. This
    updated release prevents such passwords from being
    passed back, instead returning the error, 'Attempted
    login with password having illegal chars'.

Note: dovecot versions previously shipped with Scientific Linux 5 did
not allow this behavior. This update addresses the issue above but
said issue was only present in versions of dovecot not previously
included with Scientific Linux 5."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0901&L=scientific-linux-errata&T=0&P=1781
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1828eb61"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dovecot package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"dovecot-1.0.7-7.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
