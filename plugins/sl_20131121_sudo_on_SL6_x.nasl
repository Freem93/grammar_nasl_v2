#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(71300);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/02/10 00:39:21 $");

  script_cve_id("CVE-2013-1775", "CVE-2013-2776", "CVE-2013-2777");

  script_name(english:"Scientific Linux Security Update : sudo on SL6.x i386/x86_64");
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
"A flaw was found in the way sudo handled time stamp files. An attacker
able to run code as a local user and with the ability to control the
system clock could possibly gain additional privileges by running
commands that the victim user was allowed to run via sudo, without
knowing the victim's password. (CVE-2013-1775)

It was found that sudo did not properly validate the controlling
terminal device when the tty_tickets option was enabled in the
/etc/sudoers file. An attacker able to run code as a local user could
possibly gain additional privileges by running commands that the
victim user was allowed to run via sudo, without knowing the victim's
password. (CVE-2013-2776, CVE-2013-2777)

This update also fixes the following bugs :

  - Previously, sudo did not support netgroup filtering for
    sources from the System Security Services Daemon (SSSD).
    Consequently, SSSD rules were applied to all users even
    when they did not belong to the specified netgroup. With
    this update, netgroup filtering for SSSD sources has
    been implemented. As a result, rules with a netgroup
    specification are applied only to users that are part of
    the netgroup.

  - When the sudo utility set up the environment in which it
    ran a command, it reset the value of the RLIMIT_NPROC
    resource limit to the parent's value of this limit if
    both the soft (current) and hard (maximum) values of
    RLIMIT_NPROC were not limited. An upstream patch has
    been provided to address this bug and RLIMIT_NPROC can
    now be set to 'unlimited'.

  - Due to the refactoring of the sudo code by upstream, the
    SUDO_USER variable that stores the name of the user
    running the sudo command was not logged to the
    /var/log/secure file as before. Consequently, user name
    'root' was always recorded instead of the real user
    name. With this update, the previous behavior of sudo
    has been restored. As a result, the expected user name
    is now written to /var/log/secure.

  - Due to an error in a loop condition in sudo's rule
    listing code, a buffer overflow could have occurred in
    certain cases. This condition has been fixed and the
    buffer overflow no longer occurs.

In addition, this update adds the following enhancements :

  - With this update, sudo has been modified to send debug
    messages about netgroup matching to the debug log. These
    messages should provide better understanding of how sudo
    matches netgroup database records with values from the
    running system and what the values are exactly.

  - With this update, sudo has been modified to accept the
    ipa_hostname value from the /etc/sssd/sssd.conf
    configuration file when matching netgroups."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1312&L=scientific-linux-errata&T=0&P=2951
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1610264a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected sudo, sudo-debuginfo and / or sudo-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mac OS X Sudo Password Bypass');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"sudo-1.8.6p3-12.el6")) flag++;
if (rpm_check(release:"SL6", reference:"sudo-debuginfo-1.8.6p3-12.el6")) flag++;
if (rpm_check(release:"SL6", reference:"sudo-devel-1.8.6p3-12.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
