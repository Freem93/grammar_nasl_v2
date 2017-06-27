#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(61186);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:56 $");

  script_cve_id("CVE-2011-2896");

  script_name(english:"Scientific Linux Security Update : cups on SL6.x i386/x86_64");
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
"The Common UNIX Printing System (CUPS) provides a portable printing
layer for UNIX operating systems.

A heap-based buffer overflow flaw was found in the Lempel-Ziv-Welch
(LZW) decompression algorithm implementation used by the CUPS GIF
image format reader. An attacker could create a malicious GIF image
file that, when printed, could possibly cause CUPS to crash or,
potentially, execute arbitrary code with the privileges of the 'lp'
user. (CVE-2011-2896)

These updated cups packages also provide fixes for the following 
bugs :

  - Previously CUPS was not correctly handling the language
    setting LANG=en_US.ASCII. As a consequence lpadmin,
    lpstat and lpinfo binaries were not displaying any
    output when the LANG=en_US.ASCII environment variable
    was used. As a result of this update the problem is
    fixed and the expected output is now displayed.

  - Previously the scheduler did not check for empty values
    of several configuration directives. As a consequence it
    was possible for the CUPS daemon (cupsd) to crash when a
    configuration file contained certain empty values. With
    this update the problem is fixed and cupsd no longer
    crashes when reading such a configuration file.

  - Previously when printing to a raw print queue, when
    using certain printer models, CUPS was incorrectly
    sending SNMP queries. As a consequence there was a
    noticeable 4-second delay between queueing the job and
    the start of printing. With this update the problem is
    fixed and CUPS no longer tries to collect SNMP supply
    and status information for raw print queues.

  - Previously when using the BrowsePoll directive it could
    happen that the CUPS printer polling daemon (cups-polld)
    began polling before the network interfaces were set up
    after a system boot. CUPS was then caching the failed
    hostname lookup. As a consequence no printers were found
    and the error, 'Host name lookup failure', was logged.
    With this update the code that re-initializes the
    resolver after failure in cups-polld is fixed and as a
    result CUPS will obtain the correct network settings to
    use in printer discovery.

  - The MaxJobs directive controls the maximum number of
    print jobs that are kept in memory. Previously, once the
    number of jobs reached the limit, the CUPS system failed
    to automatically purge the data file associated with the
    oldest completed job from the system in order to make
    room for a new print job. This bug has been fixed, and
    the jobs beyond the set limit are now properly purged.

  - The cups init script (/etc/rc.d/init.d/cups) uses the
    daemon function (from /etc/rc.d/init.d/functions) to
    start the cups process, but previously it did not source
    a configuration file from the /etc/sysconfig/ directory.
    As a consequence, it was difficult to cleanly set the
    nice level or cgroup for the cups daemon by setting the
    NICELEVEL or CGROUP_DAEMON variables. With this update,
    the init script is fixed.

All users of CUPS are advised to upgrade to these updated packages,
which contain backported patches to resolve these issues. After
installing this update, the cupsd daemon will be restarted
automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1112&L=scientific-linux-errata&T=0&P=2157
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1324a4be"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/06");
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
if (rpm_check(release:"SL6", reference:"cups-1.4.2-44.el6")) flag++;
if (rpm_check(release:"SL6", reference:"cups-debuginfo-1.4.2-44.el6")) flag++;
if (rpm_check(release:"SL6", reference:"cups-devel-1.4.2-44.el6")) flag++;
if (rpm_check(release:"SL6", reference:"cups-libs-1.4.2-44.el6")) flag++;
if (rpm_check(release:"SL6", reference:"cups-lpd-1.4.2-44.el6")) flag++;
if (rpm_check(release:"SL6", reference:"cups-php-1.4.2-44.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
