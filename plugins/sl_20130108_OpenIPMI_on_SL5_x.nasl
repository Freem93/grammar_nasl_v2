#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(63601);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/01/17 14:07:22 $");

  script_cve_id("CVE-2011-4339");

  script_name(english:"Scientific Linux Security Update : OpenIPMI on SL5.x i386/x86_64");
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
"It was discovered that the IPMI event daemon (ipmievd) created its
process ID (PID) file with world-writable permissions. A local user
could use this flaw to make the ipmievd init script kill an arbitrary
process when the ipmievd daemon is stopped or restarted.
(CVE-2011-4339)

Note: This issue did not affect the default configuration of OpenIPMI
as shipped with Scientific Linux 5.

This update also fixes the following bugs :

  - Prior to this update, the ipmitool utility first checked
    the IPMI hardware for Dell IPMI extensions and listed
    only supported commands when printing command usage like
    the option 'ipmtool delloem help'. On a non-Dell
    platform, the usage text was incomplete and misleading.
    This update lists all Dell OEM extensions in usage texts
    on all platforms, which allows users to check for
    command line arguments on non-Dell hardware.

  - Prior to this update, the ipmitool utility tried to
    retrieve the Sensor Data Records (SDR) from the IPMI bus
    instead of the Baseboard Management Controller (BMC) bus
    when IPMI-enabled devices reported SDR under a different
    owner than the BMC. As a consequence, the timeout
    setting for the SDR read attempt could significantly
    decrease the performance and no sensor data was shown.
    This update modifies ipmitool to read these SDR records
    from the BMC and shows the correct sensor data on these
    platforms.

  - Prior to this update, the exit code of the 'ipmitool -o
    list' option was not set correctly. As a consequence,
    'ipmitool -o list' always returned the value 1 instead
    of the expected value 0. This update modifies the
    underlying code to return the value 0 as expected.

  - Prior to this update, the 'ipmi' service init script did
    not specify the full path to the '/sbin/lsmod' and
    '/sbin/modprobe' system utilities. As a consequence, the
    init script failed when it was executed if PATH did not
    point to /sbin, for example, when running 'sudo
    /etc/init.d/ipmi'. This update modifies the init script
    so that it now contains the full path to lsmod and
    modrpobe. Now, it can be executed with sudo.

  - Prior to this update, the ipmitool man page did not list
    the '-b', '-B', '-l' and '-T' options. In this update,
    these options are documented in the ipmitool man page.

This update also adds the following enhancement :

  - Updates to the Dell-specific IPMI extension: A new
    vFlash command, which allows users to display
    information about extended SD cards; a new setled
    command, which allows users to display the backplane LED
    status; improved error descriptions; added support for
    new hardware; and updated documentation of the ipmitool
    delloem commands in the ipmitool manual page."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1301&L=scientific-linux-errata&T=0&P=967
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3f304011"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/17");
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
if (rpm_check(release:"SL5", reference:"OpenIPMI-2.0.16-16.el5")) flag++;
if (rpm_check(release:"SL5", reference:"OpenIPMI-debuginfo-2.0.16-16.el5")) flag++;
if (rpm_check(release:"SL5", reference:"OpenIPMI-devel-2.0.16-16.el5")) flag++;
if (rpm_check(release:"SL5", reference:"OpenIPMI-gui-2.0.16-16.el5")) flag++;
if (rpm_check(release:"SL5", reference:"OpenIPMI-libs-2.0.16-16.el5")) flag++;
if (rpm_check(release:"SL5", reference:"OpenIPMI-perl-2.0.16-16.el5")) flag++;
if (rpm_check(release:"SL5", reference:"OpenIPMI-python-2.0.16-16.el5")) flag++;
if (rpm_check(release:"SL5", reference:"OpenIPMI-tools-2.0.16-16.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
