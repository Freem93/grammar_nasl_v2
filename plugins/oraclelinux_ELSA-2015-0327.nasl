#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:0327 and 
# Oracle Linux Security Advisory ELSA-2015-0327 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(81722);
  script_version("$Revision: 1.26 $");
  script_cvs_date("$Date: 2016/05/20 14:21:44 $");

  script_cve_id("CVE-2014-6040", "CVE-2014-8121");
  script_bugtraq_id(68505, 68983, 69472, 71216, 72325, 73038);
  script_osvdb_id(110668, 110669, 110670, 110671, 110672, 110673, 110675, 119253);
  script_xref(name:"RHSA", value:"2015:0327");

  script_name(english:"Oracle Linux 7 : glibc (ELSA-2015-0327)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2015:0327 :

Updated glibc packages that fix two security issues and several bugs
are now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The glibc packages provide the standard C libraries (libc), POSIX
thread libraries (libpthread), standard math libraries (libm), and the
Name Server Caching Daemon (nscd) used by multiple programs on the
system. Without these libraries, the Linux system cannot function
correctly.

An out-of-bounds read flaw was found in the way glibc's iconv()
function converted certain encoded data to UTF-8. An attacker able to
make an application call the iconv() function with a specially crafted
argument could use this flaw to crash that application.
(CVE-2014-6040)

It was found that the files back end of Name Service Switch (NSS) did
not isolate iteration over an entire database from key-based look-up
API calls. An application performing look-ups on a database while
iterating over it could enter an infinite loop, leading to a denial of
service. (CVE-2014-8121)

This update also fixes the following bugs :

* Due to problems with buffer extension and reallocation, the nscd
daemon terminated unexpectedly with a segmentation fault when
processing long netgroup entries. With this update, the handling of
long netgroup entries has been corrected and nscd no longer crashes in
the described scenario. (BZ#1138520)

* If a file opened in append mode was truncated with the ftruncate()
function, a subsequent ftell() call could incorrectly modify the file
offset. This update ensures that ftell() modifies the stream state
only when it is in append mode and the buffer for the stream is not
empty. (BZ#1156331)

* A defect in the C library headers caused builds with older compilers
to generate incorrect code for the btowc() function in the older
compatibility C++ standard library. Applications calling btowc() in
the compatibility C++ standard library became unresponsive. With this
update, the C library headers have been corrected, and the
compatibility C++ standard library shipped with Red Hat Enterprise
Linux has been rebuilt. Applications that rely on the compatibility
C++ standard library no longer hang when calling btowc(). (BZ#1120490)

* Previously, when using netgroups and the nscd daemon was set up to
cache netgroup information, the sudo utility denied access to valid
users. The bug in nscd has been fixed, and sudo now works in netgroups
as expected. (BZ#1080766)

Users of glibc are advised to upgrade to these updated packages, which
fix these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-March/004874.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected glibc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Exim GHOST (glibc gethostbyname) Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"glibc-2.17-78.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"glibc-common-2.17-78.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"glibc-devel-2.17-78.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"glibc-headers-2.17-78.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"glibc-static-2.17-78.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"glibc-utils-2.17-78.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"nscd-2.17-78.0.1.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc / glibc-common / glibc-devel / glibc-headers / glibc-static / etc");
}
