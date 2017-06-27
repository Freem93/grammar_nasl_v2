#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2014-0084.
#

include("compat.inc");

if (description)
{
  script_id(80247);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/02/14 17:16:23 $");

  script_cve_id("CVE-2012-5689", "CVE-2013-2266", "CVE-2013-4854", "CVE-2014-0591", "CVE-2014-8500");
  script_bugtraq_id(57556, 58736, 61479, 64801, 71590);
  script_osvdb_id(89584, 91712, 95707, 101973, 115524);

  script_name(english:"OracleVM 3.3 : bind (OVMSA-2014-0084)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - Fix CVE-2014-8500 (#1171973)

  - Use /dev/urandom when generating rndc.key file (#951255)

  - Remove bogus file from /usr/share/doc, introduced by fix
    for bug #1092035

  - Add support for TLSA resource records (#956685)

  - Increase defaults for lwresd workers and make workers
    and client objects number configurable (#1092035)

  - Fix segmentation fault in nsupdate when -r option is
    used (#1064045)

  - Fix race condition on send buffer in host tool when
    sending UDP query (#1008827)

  - Allow authentication using TSIG in allow-notify
    configuration statement (#1044545)

  - Fix SELinux context of /var/named/chroot/etc/localtime
    (#902431)

  - Include updated named.ca file with root server addresses
    (#917356)

  - Don't generate rndc.key if there is rndc.conf on
    start-up (#997743)

  - Fix dig man page regarding how to disable IDN (#1023045)

  - Handle ICMP Destination unreachable (Protocol
    unreachable) response (#1066876)

  - Configure BIND with --with-dlopen=yes to support
    dynamically loadable DLZ drivers (#846065)

  - Fix initscript to return correct exit value when calling
    checkconfig/configtest/check/test (#848033)

  - Don't (un)mount chroot filesystem when running
    initscript command configtest with running server
    (#851123)

  - Fix zone2sqlite tool to accept zones containing '.' or
    '-' or starting with a digit (#919414)

  - Fix initscript not to mount chroot filesystem is named
    is already running (#948743)

  - Fix initscript to check if the PID in PID-file is really
    s PID of running named server (#980632)

  - Correct the installed documentation ownership (#1051283)

  - configure with --enable-filter-aaaa to enable use of
    filter-aaaa-on-v4 option (#1025008)

  - Fix race condition when destroying a resolver fetch
    object (#993612)

  - Fix the RRL functionality to include
    referrals-per-second and nodata-per-second options
    (#1036700)

  - Fix segfault on SERVFAIL to NXDOMAIN failover (#919545)

  - Fix (CVE-2014-0591)

  - Fix gssapictx memory leak (#911167)

  - fix (CVE-2013-4854)

  - fix (CVE-2013-2266)

  - ship dns/rrl.h in -devel subpkg

  - remove one bogus file from /usr/share/doc, introduced by
    RRL patch

  - fix (CVE-2012-5689)

  - add response rate limit patch (#873624)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2014-December/000250.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9f3bc143"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected bind-libs / bind-utils packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:bind-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! ereg(pattern:"^OVS" + "3\.3" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.3", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.3", reference:"bind-libs-9.8.2-0.30.rc1.el6_6.1")) flag++;
if (rpm_check(release:"OVS3.3", reference:"bind-utils-9.8.2-0.30.rc1.el6_6.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind-libs / bind-utils");
}
