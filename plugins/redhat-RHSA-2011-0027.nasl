#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0027. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51524);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/01/04 16:02:21 $");

  script_cve_id("CVE-2008-5983", "CVE-2008-5984", "CVE-2008-5985", "CVE-2008-5986", "CVE-2008-5987", "CVE-2009-0314", "CVE-2009-0315", "CVE-2009-0316", "CVE-2009-0317", "CVE-2009-4134", "CVE-2010-1449", "CVE-2010-1450", "CVE-2010-1634", "CVE-2010-2089");
  script_bugtraq_id(40361, 40363, 40365, 40370, 40862, 40863);
  script_osvdb_id(64957, 65151);
  script_xref(name:"RHSA", value:"2011:0027");

  script_name(english:"RHEL 5 : python (RHSA-2011:0027)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated python packages that fix multiple security issues, several
bugs, and add two enhancements are now available for Red Hat
Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having low
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Python is an interpreted, interactive, object-oriented programming
language.

It was found that many applications embedding the Python interpreter
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

* When starting a child process from the subprocess module in Python
2.4, the parent process could leak file descriptors if an error
occurred. This update resolves the issue. (BZ#609017)

* Prior to Python 2.7, programs that used 'ulimit -n' to enable
communication with large numbers of subprocesses could still monitor
only 1024 file descriptors at a time, which caused an exception :

ValueError: filedescriptor out of range in select()

This was due to the subprocess module using the 'select' system call.
The module now uses the 'poll' system call, removing this limitation.
(BZ#609020)

* Prior to Python 2.5, the tarfile module failed to unpack tar files
if the path was longer than 100 characters. This update backports the
tarfile module from Python 2.5 and the issue no longer occurs.
(BZ#263401)

* The email module incorrectly implemented the logic for obtaining
attachment file names: the get_filename() fallback for using the
deprecated 'name' parameter of the 'Content-Type' header erroneously
used the 'Content-Disposition' header. This update backports a fix
from Python 2.6, which resolves this issue. (BZ#644147)

* Prior to version 2.5, Python's optimized memory allocator never
released memory back to the system. The memory usage of a long-running
Python process would resemble a 'high-water mark'. This update
backports a fix from Python 2.5a1, which frees unused arenas, and adds
a non-standard sys._debugmallocstats() function, which prints
diagnostic information to stderr. Finally, when running under
Valgrind, the optimized allocator is deactivated, to allow more
convenient debugging of Python memory usage issues. (BZ#569093)

* The urllib and urllib2 modules ignored the no_proxy variable, which
could lead to programs such as 'yum' erroneously accessing a proxy
server for URLs covered by a 'no_proxy' exclusion. This update
backports fixes of urllib and urllib2, which respect the 'no_proxy'
variable, which fixes these issues. (BZ#549372)

As well, this update adds the following enhancements :

* This update introduces a new python-libs package, subsuming the
majority of the content of the core python package. This makes both
32-bit and 64-bit Python libraries available on PowerPC systems.
(BZ#625372)

* The python-libs.i386 package is now available for 64-bit Itanium
with the 32-bit Itanium compatibility mode. (BZ#644761)

All Python users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues and add these
enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-5983.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-4134.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-1449.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-1450.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-1634.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-2089.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-0027.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tkinter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2011:0027";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"python-2.4.3-43.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"python-2.4.3-43.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"python-2.4.3-43.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"python-devel-2.4.3-43.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"python-libs-2.4.3-43.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"python-libs-2.4.3-43.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"python-libs-2.4.3-43.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"python-tools-2.4.3-43.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"python-tools-2.4.3-43.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"python-tools-2.4.3-43.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"tkinter-2.4.3-43.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"tkinter-2.4.3-43.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"tkinter-2.4.3-43.el5")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python / python-devel / python-libs / python-tools / tkinter");
  }
}
