#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2012:0125 and 
# Oracle Linux Security Advisory ELSA-2012-0125 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(68455);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/06 17:02:14 $");

  script_cve_id("CVE-2009-5029", "CVE-2009-5064", "CVE-2010-0296", "CVE-2010-0830", "CVE-2011-1071", "CVE-2011-1089", "CVE-2011-1095", "CVE-2011-1659", "CVE-2011-4609");
  script_bugtraq_id(40063, 46563, 46740, 47370, 50898, 51439);
  script_osvdb_id(65077, 65078, 66751, 72796, 73407, 74278, 74883, 77508, 78316);
  script_xref(name:"RHSA", value:"2012:0125");

  script_name(english:"Oracle Linux 4 : glibc (ELSA-2012-0125)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2012:0125 :

Updated glibc packages that fix multiple security issues and one bug
are now available for Red Hat Enterprise Linux 4.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The glibc packages contain the standard C libraries used by multiple
programs on the system. These packages contain the standard C and the
standard math libraries. Without these two libraries, a Linux system
cannot function properly.

An integer overflow flaw, leading to a heap-based buffer overflow, was
found in the way the glibc library read timezone files. If a
carefully-crafted timezone file was loaded by an application linked
against glibc, it could cause the application to crash or,
potentially, execute arbitrary code with the privileges of the user
running the application. (CVE-2009-5029)

A flaw was found in the way the ldd utility identified dynamically
linked libraries. If an attacker could trick a user into running ldd
on a malicious binary, it could result in arbitrary code execution
with the privileges of the user running ldd. (CVE-2009-5064)

It was discovered that the glibc addmntent() function, used by various
mount helper utilities, did not sanitize its input properly. A local
attacker could possibly use this flaw to inject malformed lines into
the mtab (mounted file systems table) file via certain setuid mount
helpers, if the attacker were allowed to mount to an arbitrary
directory under their control. (CVE-2010-0296)

An integer overflow flaw, leading to a heap-based buffer overflow, was
found in the way the glibc library loaded ELF (Executable and Linking
Format) files. If a carefully-crafted ELF file was loaded by an
application linked against glibc, it could cause the application to
crash or, potentially, execute arbitrary code with the privileges of
the user running the application. (CVE-2010-0830)

It was discovered that the glibc fnmatch() function did not properly
restrict the use of alloca(). If the function was called on
sufficiently large inputs, it could cause an application using
fnmatch() to crash or, possibly, execute arbitrary code with the
privileges of the application. (CVE-2011-1071)

It was found that the glibc addmntent() function, used by various
mount helper utilities, did not handle certain errors correctly when
updating the mtab (mounted file systems table) file. If such utilities
had the setuid bit set, a local attacker could use this flaw to
corrupt the mtab file. (CVE-2011-1089)

It was discovered that the locale command did not produce properly
escaped output as required by the POSIX specification. If an attacker
were able to set the locale environment variables in the environment
of a script that performed shell evaluation on the output of the
locale command, and that script were run with different privileges
than the attacker's, it could execute arbitrary code with the
privileges of the script. (CVE-2011-1095)

An integer overflow flaw was found in the glibc fnmatch() function. If
an attacker supplied a long UTF-8 string to an application linked
against glibc, it could cause the application to crash.
(CVE-2011-1659)

A denial of service flaw was found in the remote procedure call (RPC)
implementation in glibc. A remote attacker able to open a large number
of connections to an RPC service that is using the RPC implementation
from glibc, could use this flaw to make that service use an excessive
amount of CPU time. (CVE-2011-4609)

Red Hat would like to thank the Ubuntu Security Team for reporting
CVE-2010-0830, and Dan Rosenberg for reporting CVE-2011-1089. The
Ubuntu Security Team acknowledges Dan Rosenberg as the original
reporter of CVE-2010-0830.

This update also fixes the following bug :

* When using an nscd package that is a different version than the
glibc package, the nscd service could fail to start. This update makes
the nscd package require a specific glibc version to prevent this
problem. (BZ#657009)

Users should upgrade to these updated packages, which resolve these
issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-February/002604.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected glibc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-profile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nptl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/14");
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
if (! ereg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 4", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL4", reference:"glibc-2.3.4-2.57")) flag++;
if (rpm_check(release:"EL4", reference:"glibc-common-2.3.4-2.57")) flag++;
if (rpm_check(release:"EL4", reference:"glibc-devel-2.3.4-2.57")) flag++;
if (rpm_check(release:"EL4", reference:"glibc-headers-2.3.4-2.57")) flag++;
if (rpm_check(release:"EL4", reference:"glibc-profile-2.3.4-2.57")) flag++;
if (rpm_check(release:"EL4", reference:"glibc-utils-2.3.4-2.57")) flag++;
if (rpm_check(release:"EL4", reference:"nptl-devel-2.3.4-2.57")) flag++;
if (rpm_check(release:"EL4", reference:"nscd-2.3.4-2.57")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc / glibc-common / glibc-devel / glibc-headers / glibc-profile / etc");
}
