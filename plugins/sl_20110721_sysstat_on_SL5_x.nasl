#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(61095);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:56 $");

  script_cve_id("CVE-2007-3852");

  script_name(english:"Scientific Linux Security Update : sysstat on SL5.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Scientific Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The sysstat package contains a set of utilities which enable system
monitoring of disks, network, and other I/O activity.

It was found that the sysstat initscript created a temporary file in
an insecure way. A local attacker could use this flaw to create
arbitrary files via a symbolic link attack. (CVE-2007-3852)

This update fixes the following bugs :

  - On systems under heavy load, the sadc utility would
    sometimes output the following error message if a
    write() call was unable to write all of the requested
    input :

'Cannot write data to system activity file: Success.'

In this updated package, the sadc utility tries to write the remaining
input, resolving this issue.

  - On the Itanium architecture, the 'sar -I' command
    provided incorrect information about the interrupt
    statistics of the system. With this update, the 'sar -I'
    command has been disabled for this architecture,
    preventing this bug.

  - Previously, the 'iostat -n' command used invalid data to
    create statistics for read and write operations. With
    this update, the data source for these statistics has
    been fixed, and the iostat utility now returns correct
    information.

  - The 'sar -d' command used to output invalid data about
    block devices. With this update, the sar utility
    recognizes disk registration and disk overflow
    statistics properly, and only correct and relevant data
    is now displayed.

  - Previously, the sar utility set the maximum number of
    days to be logged in one month too high. Consequently,
    data from a month was appended to data from the
    preceding month. With this update, the maximum number of
    days has been set to 25, and data from a month now
    correctly replaces data from the preceding month.

  - In previous versions of the iostat utility, the number
    of NFS mount points was hard-coded. Consequently,
    various issues occurred while iostat was running and NFS
    mount points were mounted or unmounted; certain values
    in iostat reports overflowed and some mount points were
    not reported at all. With this update, iostat properly
    recognizes when an NFS mount point mounts or unmounts,
    fixing these issues.

  - When a device name was longer than 13 characters, the
    iostat utility printed a redundant new line character,
    making its output less readable. This bug has been fixed
    and now, no extra characters are printed if a long
    device name occurs in iostat output.

  - Previously, if kernel interrupt counters overflowed, the
    sar utility provided confusing output. This bug has been
    fixed and the sum of interrupts is now reported
    correctly.

  - When some processors were disabled on a multi-processor
    system, the sar utility sometimes failed to provide
    information about the CPU activity. With this update,
    the uptime of a single processor is used to compute the
    statistics, rather than the total uptime of all
    processors, and this bug no longer occurs.

  - Previously, the mpstat utility wrongly interpreted data
    about processors in the system. Consequently, it
    reported a processor that did not exist. This bug has
    been fixed and non-existent CPUs are no longer reported
    by mpstat.

  - Previously, there was no easy way to enable the
    collection of statistics about disks and interrupts.
    Now, the SADC_OPTIONS variable can be used to set
    parameters for the sadc utility, fixing this bug.

  - The read_uptime() function failed to close its open file
    upon exit. A patch has been provided to fix this bug.

This update also adds the following enhancement :

  - With this update, the cifsiostat utility has been added
    to the sysstat package to provide CIFS (Common Internet
    File System) mount point I/O statistics.

All sysstat users are advised to upgrade to this updated package,
which contains backported patches to correct these issues and add this
enhancement."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1108&L=scientific-linux-errata&T=0&P=1028
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f31fc978"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected sysstat package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/21");
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
if (rpm_check(release:"SL5", reference:"sysstat-7.0.2-11.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
