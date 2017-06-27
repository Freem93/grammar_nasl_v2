#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(65009);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/03/05 11:50:59 $");

  script_cve_id("CVE-2011-2166", "CVE-2011-2167", "CVE-2011-4318");

  script_name(english:"Scientific Linux Security Update : dovecot on SL6.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two flaws were found in the way some settings were enforced by the
script-login functionality of Dovecot. A remote, authenticated user
could use these flaws to bypass intended access restrictions or
conduct a directory traversal attack by leveraging login scripts.
(CVE-2011-2166, CVE-2011-2167)

A flaw was found in the way Dovecot performed remote server identity
verification, when it was configured to proxy IMAP and POP3
connections to remote hosts using TLS/SSL protocols. A remote attacker
could use this flaw to conduct man-in-the-middle attacks using an
X.509 certificate issued by a trusted Certificate Authority (for a
different name). (CVE-2011-4318)

This update also fixes the following bug :

  - When a new user first accessed their IMAP inbox, Dovecot
    was, under some circumstances, unable to change the
    group ownership of the inbox directory in the user's
    Maildir location to match that of the user's mail spool
    (/var/mail/$USER). This correctly generated an 'Internal
    error occurred' message. However, with a subsequent
    attempt to access the inbox, Dovecot saw that the
    directory already existed and proceeded with its
    operation, leaving the directory with incorrectly set
    permissions. This update corrects the underlying
    permissions setting error. When a new user now accesses
    their inbox for the first time, and it is not possible
    to set group ownership, Dovecot removes the created
    directory and generates an error message instead of
    keeping the directory with incorrect group ownership.

After installing the updated packages, the dovecot service will be
restarted automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1303&L=scientific-linux-errata&T=0&P=459
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6b5c721a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"dovecot-2.0.9-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"dovecot-debuginfo-2.0.9-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"dovecot-devel-2.0.9-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"dovecot-mysql-2.0.9-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"dovecot-pgsql-2.0.9-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"dovecot-pigeonhole-2.0.9-5.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
