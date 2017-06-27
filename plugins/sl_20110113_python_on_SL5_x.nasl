#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60935);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:42:09 $");

  script_cve_id("CVE-2008-5983", "CVE-2009-4134", "CVE-2010-1449", "CVE-2010-1450", "CVE-2010-1634", "CVE-2010-2089");

  script_name(english:"Scientific Linux Security Update : python on SL5.x i386/x86_64");
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
"It was found that many applications embedding the Python interpreter
did not specify a valid full path to the script or application when
calling the PySys_SetArgv API function, which could result in the
addition of the current working directory to the module search path
(sys.path). A local attacker able to trick a victim into running such
an application in an attacker-controlled directory could use this flaw
to execute code with the victim's privileges. This update adds the
PySys_SetArgvEx API. Developers can modify their applications to use
this new API, which sets sys.argv without modifying sys.path.
(CVE-2008-5983)

Multiple flaws were found in the Python rgbimg module. If an
application written in Python was using the rgbimg module and loaded a
specially crafted SGI image file, it could cause the application to
crash or, possibly, execute arbitrary code with the privileges of the
user running the application. (CVE-2009-4134, CVE-2010-1449,
CVE-2010-1450)

Multiple flaws were found in the Python audioop module. Supplying
certain inputs could cause the audioop module to crash or, possibly,
execute arbitrary code. (CVE-2010-1634, CVE-2010-2089)

This update also fixes the following bugs :

  - When starting a child process from the subprocess module
    in Python 2.4, the parent process could leak file
    descriptors if an error occurred. This update resolves
    the issue. (BZ#609017)

  - Prior to Python 2.7, programs that used 'ulimit -n' to
    enable communication with large numbers of subprocesses
    could still monitor only 1024 file descriptors at a
    time, which caused an exception :

    ValueError: filedescriptor out of range in select()

This was due to the subprocess module using the 'select' system call.
The module now uses the 'poll' system call, removing this limitation.
(BZ#609020)

  - Prior to Python 2.5, the tarfile module failed to unpack
    tar files if the path was longer than 100 characters.
    This update backports the tarfile module from Python 2.5
    and the issue no longer occurs. (BZ#263401)

  - The email module incorrectly implemented the logic for
    obtaining attachment file names: the get_filename()
    fallback for using the deprecated 'name' parameter of
    the 'Content-Type' header erroneously used the
    'Content-Disposition' header. This update backports a
    fix from Python 2.6, which resolves this issue.
    (BZ#644147)

  - Prior to version 2.5, Python's optimized memory
    allocator never released memory back to the system. The
    memory usage of a long-running Python process would
    resemble a 'high-water mark'. This update backports a
    fix from Python 2.5a1, which frees unused arenas, and
    adds a non-standard sys._debugmallocstats() function,
    which prints diagnostic information to stderr. Finally,
    when running under Valgrind, the optimized allocator is
    deactivated, to allow more convenient debugging of
    Python memory usage issues. (BZ#569093)

  - The urllib and urllib2 modules ignored the no_proxy
    variable, which could lead to programs such as 'yum'
    erroneously accessing a proxy server for URLs covered by
    a 'no_proxy' exclusion. This update backports fixes of
    urllib and urllib2, which respect the 'no_proxy'
    variable, which fixes these issues. (BZ#549372)

As well, this update adds the following enhancements :

  - This update introduces a new python-libs package,
    subsuming the majority of the content of the core python
    package. This makes both 32-bit and 64-bit Python
    libraries available on PowerPC systems. (BZ#625372)

  - The python-libs.i386 package is now available for 64-bit
    Itanium with the 32-bit Itanium compatibility mode.
    (BZ#644761)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1102&L=scientific-linux-errata&T=0&P=1728
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?528a21e5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=263401"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=549372"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=569093"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=609017"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=609020"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=625372"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=644147"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=644761"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"python-2.4.3-43.el5")) flag++;
if (rpm_check(release:"SL5", reference:"python-devel-2.4.3-43.el5")) flag++;
if (rpm_check(release:"SL5", reference:"python-libs-2.4.3-43.el5")) flag++;
if (rpm_check(release:"SL5", reference:"python-tools-2.4.3-43.el5")) flag++;
if (rpm_check(release:"SL5", reference:"tkinter-2.4.3-43.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
