#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:0412 and 
# Oracle Linux Security Advisory ELSA-2011-0412 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68244);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/04/28 19:01:50 $");

  script_cve_id("CVE-2010-0296", "CVE-2010-3847", "CVE-2011-0536", "CVE-2011-1071", "CVE-2011-1095", "CVE-2011-1658", "CVE-2011-1659");
  script_bugtraq_id(46563, 46740, 64465);
  script_osvdb_id(65078, 66751, 68721, 72796, 73407);
  script_xref(name:"RHSA", value:"2011:0412");

  script_name(english:"Oracle Linux 5 : glibc (ELSA-2011-0412)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2011:0412 :

Updated glibc packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The glibc packages contain the standard C libraries used by multiple
programs on the system. These packages contain the standard C and the
standard math libraries. Without these two libraries, a Linux system
cannot function properly.

The fix for CVE-2010-3847 introduced a regression in the way the
dynamic loader expanded the $ORIGIN dynamic string token specified in
the RPATH and RUNPATH entries in the ELF library header. A local
attacker could use this flaw to escalate their privileges via a setuid
or setgid program using such a library. (CVE-2011-0536)

It was discovered that the glibc addmntent() function did not sanitize
its input properly. A local attacker could possibly use this flaw to
inject malformed lines into /etc/mtab via certain setuid mount
helpers, if the attacker were allowed to mount to an arbitrary
directory under their control. (CVE-2010-0296)

It was discovered that the glibc fnmatch() function did not properly
restrict the use of alloca(). If the function was called on
sufficiently large inputs, it could cause an application using
fnmatch() to crash or, possibly, execute arbitrary code with the
privileges of the application. (CVE-2011-1071)

It was discovered that the locale command did not produce properly
escaped output as required by the POSIX specification. If an attacker
were able to set the locale environment variables in the environment
of a script that performed shell evaluation on the output of the
locale command, and that script were run with different privileges
than the attacker's, it could execute arbitrary code with the
privileges of the script. (CVE-2011-1095)

All users should upgrade to these updated packages, which contain
backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-April/002053.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected glibc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"glibc-2.5-58.el5_6.2")) flag++;
if (rpm_check(release:"EL5", reference:"glibc-common-2.5-58.el5_6.2")) flag++;
if (rpm_check(release:"EL5", reference:"glibc-devel-2.5-58.el5_6.2")) flag++;
if (rpm_check(release:"EL5", reference:"glibc-headers-2.5-58.el5_6.2")) flag++;
if (rpm_check(release:"EL5", reference:"glibc-utils-2.5-58.el5_6.2")) flag++;
if (rpm_check(release:"EL5", reference:"nscd-2.5-58.el5_6.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc / glibc-common / glibc-devel / glibc-headers / glibc-utils / etc");
}
