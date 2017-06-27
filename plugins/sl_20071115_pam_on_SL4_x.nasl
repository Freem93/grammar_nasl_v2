#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60308);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:52 $");

  script_cve_id("CVE-2007-1716", "CVE-2007-3102");

  script_name(english:"Scientific Linux Security Update : pam on SL4.x i386/x86_64");
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
"A flaw was found in the way pam_console set console device
permissions. It was possible for various console devices to retain
ownership of the console user after logging out, possibly leaking
information to another local user. (CVE-2007-1716)

A flaw was found in the way the PAM library wrote account names to the
audit subsystem. An attacker could inject strings containing parts of
audit messages, which could possibly mislead or confuse audit log
parsing tools. (CVE-2007-3102)

As well, these updated packages fix the following bugs :

  - the pam_xauth module, which is used for copying the X11
    authentication cookie, did not reset the 'XAUTHORITY'
    variable in certain circumstances, causing unnecessary
    delays when using su command.

  - when calculating password similarity, pam_cracklib
    disregarded changes to the last character in passwords
    when 'difok=x' (where 'x' is the number of characters
    required to change) was configured in
    '/etc/pam.d/system-auth'. This resulted in password
    changes that should have been successful to fail with
    the following error :

BAD PASSWORD: is too similar to the old one

This issue has been resolved in these updated packages.

  - the pam_limits module, which provides setting up system
    resources limits for user sessions, reset the nice
    priority of the user session to '0' if it was not
    configured otherwise in the '/etc/security/limits.conf'
    configuration file.

These updated packages add the following enhancement :

  - a new PAM module, pam_tally2, which allows accounts to
    be locked after a maximum number of failed log in
    attempts."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0711&L=scientific-linux-errata&T=0&P=3261
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?752cad11"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pam and / or pam-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/15");
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
if (rpm_check(release:"SL4", reference:"pam-0.77-66.23")) flag++;
if (rpm_check(release:"SL4", reference:"pam-devel-0.77-66.23")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
