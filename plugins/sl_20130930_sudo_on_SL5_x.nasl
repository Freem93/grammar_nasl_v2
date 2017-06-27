#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(70392);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/02/10 00:39:21 $");

  script_cve_id("CVE-2013-1775", "CVE-2013-1776", "CVE-2013-2776");

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
password. (CVE-2013-1776, CVE-2013-2776)

This update also fixes the following bugs :

  - Due to a bug in the cycle detection algorithm of the
    visudo utility, visudo incorrectly evaluated certain
    alias definitions in the /etc/sudoers file as cycles.
    Consequently, a warning message about undefined aliases
    appeared. This bug has been fixed, /etc/sudoers is now
    parsed correctly by visudo and the warning message no
    longer appears.

  - Previously, the 'sudo -l' command did not parse the
    /etc/sudoers file correctly if it contained an Active
    Directory (AD) group. The file was parsed only up to the
    first AD group information and then the parsing failed
    with the following message :

sudo: unable to cache group ADDOM\admingroup, already exists

With this update, the underlying code has been modified and 'sudo -l'
now parses /etc/sudoers containing AD groups correctly.

  - Previously, the sudo utility did not escape the
    backslash characters contained in user names properly.
    Consequently, if a system used sudo integrated with LDAP
    or Active Directory (AD) as the primary authentication
    mechanism, users were not able to authenticate on that
    system. With this update, sudo has been modified to
    process LDAP and AD names correctly and the
    authentication process now works as expected.

  - Prior to this update, the 'visudo -s (strict)' command
    incorrectly parsed certain alias definitions.
    Consequently, an error message was issued. The bug has
    been fixed, and parsing errors no longer occur when
    using 'visudo - -s'."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1310&L=scientific-linux-errata&T=0&P=934
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3ba6469d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected sudo and / or sudo-debuginfo packages."
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

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/11");
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
if (rpm_check(release:"SL5", reference:"sudo-1.7.2p1-28.el5")) flag++;
if (rpm_check(release:"SL5", reference:"sudo-debuginfo-1.7.2p1-28.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
