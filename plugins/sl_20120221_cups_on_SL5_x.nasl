#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61259);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:57 $");

  script_cve_id("CVE-2011-2896");

  script_name(english:"Scientific Linux Security Update : cups on SL5.x i386/x86_64");
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
layer for Linux, UNIX, and similar operating systems.

A heap-based buffer overflow flaw was found in the Lempel-Ziv-Welch
(LZW) decompression algorithm implementation used by the CUPS GIF
image format reader. An attacker could create a malicious GIF image
file that, when printed, could possibly cause CUPS to crash or,
potentially, execute arbitrary code with the privileges of the 'lp'
user. (CVE-2011-2896)

This update also fixes the following bugs :

  - Prior to this update, the 'Show Completed Jobs,' 'Show
    All Jobs,' and 'Show Active Jobs' buttons returned
    results globally across all printers and not the results
    for the specified printer. With this update, jobs from
    only the selected printer are shown.

  - Prior to this update, the code of the serial backend
    contained a wrong condition. As a consequence, print
    jobs on the raw print queue could not be canceled. This
    update modifies the condition in the serial backend
    code. Now, the user can cancel these print jobs.

  - Prior to this update, the textonly filter did not work
    if used as a pipe, for example when the command line did
    not specify the filename and the number of copies was
    always 1. This update modifies the condition in the
    textonly filter. Now, the data are sent to the printer
    regardless of the number of copies specified.

  - Prior to this update, the file descriptor count
    increased until it ran out of resources when the cups
    daemon was running with enabled Security-Enhanced Linux
    (SELinux) features. With this update, all resources are
    allocated only once.

  - Prior to this update, CUPS incorrectly handled the
    en_US.ASCII value for the LANG environment variable. As
    a consequence, the lpadmin, lpstat, and lpinfo binaries
    failed to write to standard output if using LANG with
    the value. This update fixes the handling of the
    en_US.ASCII value and the binaries now write to standard
    output properly.

All users of cups are advised to upgrade to these updated packages,
which contain backported patches to resolve these issues. After
installing this update, the cupsd daemon will be restarted
automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1203&L=scientific-linux-errata&T=0&P=2530
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4d5f0cd4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

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
if (rpm_check(release:"SL5", reference:"cups-1.3.7-30.el5")) flag++;
if (rpm_check(release:"SL5", reference:"cups-debuginfo-1.3.7-30.el5")) flag++;
if (rpm_check(release:"SL5", reference:"cups-devel-1.3.7-30.el5")) flag++;
if (rpm_check(release:"SL5", reference:"cups-libs-1.3.7-30.el5")) flag++;
if (rpm_check(release:"SL5", reference:"cups-lpd-1.3.7-30.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
