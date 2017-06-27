#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(61271);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:57 $");

  script_cve_id("CVE-2011-0010");

  script_name(english:"Scientific Linux Security Update : sudo on SL5.x i386/x86_64");
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
"The sudo (superuser do) utility allows system administrators to give
certain users the ability to run commands as root.

A flaw was found in the sudo password checking logic. In
configurations where the sudoers settings allowed a user to run a
command using sudo with only the group ID changed, sudo failed to
prompt for the user's password before running the specified command
with the elevated group privileges. (CVE-2011-0010)

In addition, this update fixes the following bugs :

  - A NULL pointer dereference bug caused the sudo utility
    to terminate unexpectedly with a segmentation fault.
    This happened if the utility was run with the -g option
    and configured not to demand the password from the user
    who ran the sudo utility. With this update, the code has
    been modified and the problem no longer occurs.

  - The sudo utility failed to load sudoers from an LDAP
    (Lightweight Directory Access Protocol) server after the
    sudo tool was upgraded. This happened because the
    upgraded nsswitch.conf file did not contain the
    instruction to search for sudoers on the LDAP server.
    This update adds the lost instruction to
    /etc/nsswitch.conf and the system searches for sources
    of sudoers on the local file system and then on LDAP, if
    applicable.

  - The sudo tool interpreted a Runas alias specifying a
    group incorrectly as a user alias and the alias seemed
    to be ignored. With this update, the code for
    interpreting such aliases has been modified and the
    Runas group aliases are honored as expected.

  - Prior to this update, sudo did not parse comment
    characters (#) in the ldap.conf file correctly and could
    fail to work. With this update, parsing of the LDAP
    configuration file has been modified and the comment
    characters are parsed correctly.

  - The sudo utility formats its output to fit the width of
    the terminal window. However, this behavior is
    undesirable if the output is redirected through a
    pipeline. With this update, the output formatting is not
    applied in the scenario described.

  - Previously, the sudo utility performed Security-Enhanced
    Linux (SELinux) related initialization after switching
    to an unprivileged user. This prevented the correct
    setup of the SELinux environment before executing the
    specified command and could potentially cause an access
    denial. The bug has been fixed by backporting the
    SELinux related code and the execution model from a
    newer version of sudo.

  - On execv(3) function failure, the sudo tool executed an
    auditing call before reporting the failure. The call
    reset the error state and, consequently, the tool
    incorrectly reported that the command succeeded. With
    this update, the code has been modified and the problem
    no longer occurs.

All users of sudo are advised to upgrade to this updated package,
which resolves these issues."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1203&L=scientific-linux-errata&T=0&P=3419
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3a9251d0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected sudo and / or sudo-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/21");
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
if (rpm_check(release:"SL5", reference:"sudo-1.7.2p1-13.el5")) flag++;
if (rpm_check(release:"SL5", reference:"sudo-debuginfo-1.7.2p1-13.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
