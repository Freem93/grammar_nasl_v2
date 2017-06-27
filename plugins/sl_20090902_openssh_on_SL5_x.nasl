#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60657);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:53 $");

  script_cve_id("CVE-2008-5161");

  script_name(english:"Scientific Linux Security Update : openssh on SL5.x i386/x86_64");
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
"CVE-2008-5161 OpenSSH: Plaintext Recovery Attack against CBC ciphers

A flaw was found in the SSH protocol. An attacker able to perform a
man-in-the-middle attack may be able to obtain a portion of plain text
from an arbitrary ciphertext block when a CBC mode cipher was used to
encrypt SSH communication. This update helps mitigate this attack:
OpenSSH clients and servers now prefer CTR mode ciphers to CBC mode,
and the OpenSSH server now reads SSH packets up to their full possible
length when corruption is detected, rather than reporting errors
early, reducing the possibility of successful plain text recovery.
(CVE-2008-5161)

This update also fixes the following bug :

  - the ssh client hung when trying to close a session in
    which a background process still held tty file
    descriptors open. With this update, this so-called 'hang
    on exit' error no longer occurs and the ssh client
    closes the session immediately. (BZ#454812)

In addition, this update adds the following enhancements :

  - the SFTP server can now chroot users to various
    directories, including a user's home directory, after
    log in. A new configuration option -- ChrootDirectory --
    has been added to '/etc/ssh/sshd_config' for setting
    this up (the default is not to chroot users). Details
    regarding configuring this new option are in the
    sshd_config(5) manual page. (BZ#440240)

  - the executables which are part of the OpenSSH FIPS
    module which is being validated will check their
    integrity and report their FIPS mode status to the
    system log or to the terminal. (BZ#467268, BZ#492363)

After installing this update, the OpenSSH server daemon (sshd) will be
restarted automatically.

Note: fipscheck update needed for dependencies."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0909&L=scientific-linux-errata&T=0&P=1808
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7b57f327"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=440240"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=454812"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=467268"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=492363"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_cwe_id(200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/02");
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
if (rpm_check(release:"SL5", reference:"fipscheck-1.2.0-1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"fipscheck-devel-1.2.0-1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"fipscheck-lib-1.2.0-1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"openssh-4.3p2-36.el5")) flag++;
if (rpm_check(release:"SL5", reference:"openssh-askpass-4.3p2-36.el5")) flag++;
if (rpm_check(release:"SL5", reference:"openssh-clients-4.3p2-36.el5")) flag++;
if (rpm_check(release:"SL5", reference:"openssh-server-4.3p2-36.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
