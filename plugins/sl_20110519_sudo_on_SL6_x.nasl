#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61050);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:55 $");

  script_cve_id("CVE-2011-0010");

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
"The sudo (superuser do) utility allows system administrators to give
certain users the ability to run commands as root.

A flaw was found in the sudo password checking logic. In
configurations where the sudoers settings allowed a user to run a
command using sudo with only the group ID changed, sudo failed to
prompt for the user's password before running the specified command
with the elevated group privileges. (CVE-2011-0010)

This update also fixes the following bugs :

  - When the '/etc/sudoers' file contained entries with
    multiple hosts, running the 'sudo -l' command
    incorrectly reported that a certain user does not have
    permissions to use sudo on the system. With this update,
    running the 'sudo -l' command now produces the correct
    output. (BZ#603823)

  - Prior to this update, the manual page for sudoers.ldap
    was not installed, even though it contains important
    information on how to set up an LDAP (Lightweight
    Directory Access Protocol) sudoers source, and other
    documents refer to it. With this update, the manual page
    is now properly included in the package. Additionally,
    various POD files have been removed from the package, as
    they are required for build purposes only. (BZ#634159)

  - The previous version of sudo did not use the same
    location for the LDAP configuration files as the
    nss_ldap package. This has been fixed and sudo now looks
    for these files in the same location as the nss_ldap
    package. (BZ#652726)

  - When a file was edited using the 'sudo -e file' or the
    'sudoedit file' command, the editor being executed for
    this task was logged only as 'sudoedit'. With this
    update, the full path to the executable being used as an
    editor is now logged (instead of 'sudoedit').
    (BZ#665131)

  - A comment regarding the 'visiblepw' option of the
    'Defaults' directive has been added to the default
    '/etc/sudoers' file to clarify its usage. (BZ#688640)

  - This erratum upgrades sudo to upstream version 1.7.4p5,
    which provides a number of bug fixes and enhancements
    over the previous version. (BZ#615087)

All users of sudo are advised to upgrade to this updated package,
which resolves these issues."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1106&L=scientific-linux-errata&T=0&P=75
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d56e2856"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=603823"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=615087"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=634159"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=652726"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=665131"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=688640"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected sudo and / or sudo-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/19");
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
if (rpm_check(release:"SL6", reference:"sudo-1.7.4p5-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"sudo-debuginfo-1.7.4p5-5.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
