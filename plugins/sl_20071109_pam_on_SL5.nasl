#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60297);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:52 $");

  script_cve_id("CVE-2007-1716", "CVE-2007-3102");

  script_name(english:"Scientific Linux Security Update : pam on SL5.x");
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
"Problem description :

A flaw was found in the way pam_console set console device
permissions. It was possible for various console devices to retain
ownership of the console user after logging out, possibly leaking
information to another local user. (CVE-2007-1716)

A flaw was found in the way the PAM library wrote account names to the
audit subsystem. An attacker could inject strings containing parts of
audit messages which could possibly mislead or confuse audit log
parsing tools. (CVE-2007-3102)

As well, these updated packages fix the following bugs :

  - truncated MD5-hashed passwords in '/etc/shadow' were
    treated as valid, resulting in insecure and invalid
    passwords.

  - the pam_namespace module did not convert context names
    to raw format and did not unmount polyinstantiated
    directories in some cases. It also crashed when an
    unknown user name was used in
    '/etc/security/namespace.conf', the pam_namespace
    configuration file.

  - the pam_selinux module was not relabeling the
    controlling tty correctly, and in some cases it did not
    send complete information about user role and level
    change to the audit subsystem.

These updated packages add the following enhancements :

  - pam_limits module now supports parsing additional config
    files placed into the /etc/security/limits.d/ directory.
    These files are read after the main configuration file.

  - the modules pam_limits, pam_access, and pam_time now
    send a message to the audit subsystem when a user is
    denied access based on the number of login sessions,
    origin of user, and time of login.

  - pam_unix module security properties were improved.
    Functionality in the setuid helper binary, unix_chkpwd,
    which was not required for user authentication, was
    moved to a new non-setuid helper binary, unix_update."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0711&L=scientific-linux-errata&T=0&P=987
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?65b3b8fe"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pam and / or pam-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

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
if (rpm_check(release:"SL5", reference:"pam-0.99.6.2-3.26.el5")) flag++;
if (rpm_check(release:"SL5", reference:"pam-devel-0.99.6.2-3.26.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
