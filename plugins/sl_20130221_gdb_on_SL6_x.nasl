#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(64951);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/03/07 11:50:57 $");

  script_cve_id("CVE-2011-4355");

  script_name(english:"Scientific Linux Security Update : gdb on SL6.x i386/x86_64");
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
"GDB tried to auto-load certain files (such as GDB scripts, Python
scripts, and a thread debugging library) from the current working
directory when debugging programs. This could result in the execution
of arbitrary code with the user's privileges when GDB was run in a
directory that has untrusted content. (CVE-2011-4355)

With this update, GDB no longer auto-loads files from the current
directory and only trusts certain system directories by default. The
list of trusted directories can be viewed and modified using the 'show
auto-load safe-path' and 'set auto-load safe-path' GDB commands. Refer
to the GDB manual, linked to in the References, for further
information.

This update also fixes the following bugs :

  - When a struct member was at an offset greater than 256
    MB, the resulting bit position within the struct
    overflowed and caused an invalid memory access by GDB.
    With this update, the code has been modified to ensure
    that GDB can access such positions.

  - When a thread list of the core file became corrupted,
    GDB did not print this list but displayed the 'Cannot
    find new threads: generic error' error message instead.
    With this update, GDB has been modified and it now
    prints the thread list of the core file as expected.

  - GDB did not properly handle debugging of multiple
    binaries with the same build ID. This update modifies
    GDB to use symbolic links created for particular
    binaries so that debugging of binaries that share a
    build ID now proceeds as expected. Debugging of live
    programs and core files is now more user-friendly."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1302&L=scientific-linux-errata&T=0&P=5282
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b005856c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected gdb, gdb-debuginfo and / or gdb-gdbserver
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/01");
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
if (rpm_check(release:"SL6", reference:"gdb-7.2-60.el6")) flag++;
if (rpm_check(release:"SL6", reference:"gdb-debuginfo-7.2-60.el6")) flag++;
if (rpm_check(release:"SL6", reference:"gdb-gdbserver-7.2-60.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
