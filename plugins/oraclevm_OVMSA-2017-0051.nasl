#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2017-0051.
#

include("compat.inc");

if (description)
{
  script_id(99078);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/03/30 13:31:43 $");

  script_cve_id("CVE-2014-9761", "CVE-2015-7547", "CVE-2015-8776", "CVE-2015-8778", "CVE-2015-8779");
  script_osvdb_id(133568, 133574, 133577, 133580, 134584);
  script_xref(name:"TRA", value:"TRA-2017-08");

  script_name(english:"OracleVM 3.3 / 3.4 : glibc (OVMSA-2017-0051)");
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

  - Update newmode size to fix a possible corruption

  - Fix AF_INET6 getaddrinfo with nscd (#1416496)

  - Update tests for struct sockaddr_storage changes
    (#1338673)

  - Use FL_CLOEXEC in internal calls to fopen (#1012343).

  - Fix CVE-2015-8779 glibc: Unbounded stack allocation in
    catopen function (#1358015).

  - Make padding in struct sockaddr_storage explicit
    (#1338673)

  - Fix detection of Intel FMA hardware (#1384281).

  - Add support for, ur_IN, and wal_ET locales (#1101858).

  - Change malloc/tst-malloc-thread-exit.c to use fewer
    threads and avoid timeout (#1318380).

  - df can fail on some systems (#1307029).

  - Log uname, cpuinfo, meminfo during build (#1307029).

  - Draw graphs for heap and stack only if MAXSIZE_HEAP and
    MAXSIZE_STACK are non-zero (#1331304).

  - Avoid unneeded calls to __check_pf in getadddrinfo
    (#1270950)

  - Fix CVE-2015-8778 glibc: Integer overflow in hcreate and
    hcreate_r (#1358013).

  - Fix CVE-2015-8776 glibc: Segmentation fault caused by
    passing out-of-range data to strftime (#1358011).

  - tzdata-update: Ignore umask setting (#1373646)

  - CVE-2014-9761: Fix unbounded stack allocation in nan*
    (#1358014)

  - Avoid using uninitialized data in getaddrinfo (#1223095)

  - Update fix for CVE-2015-7547 (#1296029).

  - Create helper threads with enough stack for POSIX AIO
    and timers (#1299319).

  - Fix CVE-2015-7547: getaddrinfo stack-based buffer
    overflow (#1296029).

  - Update malloc free_list cyclic fix (#1264189).

  - Update tzdata-update changes (#1200555).

  - Avoid redundant shift character in iconv output at block
    boundary (#1293914).

  - Clean up testsuite results when testing with newer
    kernels (#1293464).

  - Do not rewrite /etc/localtime if it is a symbolic link.
    (#1200555)

  - Support long lines in /etc/hosts (#1020263).

  - Avoid aliasing warning in tst-rec-dlopen (#1291444)

  - Don't touch user-controlled stdio locks in forked child
    (#1275384).

  - Increase the limit of shared libraries that can use
    static TLS (#1198802).

  - Avoid PLT in libm for feupdateenv (#1186104).

  - Allow PLT entry in libc for _Unwind_Find_FDE on
    s390/s390x (#1186104).

  - Provide /etc/gai.conf only in the glibc package.
    (#1223818)

  - Change first day of the week to Monday for the ca_ES
    locale. (#1011900)

  - Update BIG5-HKSCS charmap to HKSCS-2008. (#1211748)

  - Rename Oriya locale to Odia. (#1091334)

  - Avoid hang in gethostbyname_r due to missing mutex
    unlocking (#1192621)

  - Avoid ld.so crash when audit modules provide path
    (#1211098)

  - Suppress expected backtrace in tst-malloc-backtrace
    (#1276633)

  - Avoid PLT for memmem (#1186104).

  - Fix up a missing dependency in the Makefile (#1219627).

  - Reduce lock contention in __tz_convert (#1244585).

  - Prevent the malloc arena free list from becoming cyclic
    (#1264189)

  - Remove legacy IA64 support (#1246145).

  - Check for NULL arena pointer in _int_pvalloc (#1246656).

  - Don't change no_dyn_threshold on mallopt failure
    (#1246660).

  - Unlock main arena after allocation in calloc (#1245731).

  - Enable robust malloc change again (#1245731).

  - Fix perturbing in malloc on free and simply perturb_byte
    (#1245731).

  - Don't fall back to mmap prematurely (#1245731).

  - The malloc deadlock avoidance support has been
    temporarily removed since it triggers deadlocks in
    certain applications (#1243824)."
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2017-March/000661.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?583f14a4"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2017-March/000670.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8cce5281"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2017-08"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/29");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^OVS" + "(3\.3|3\.4)" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.3 / 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.3", reference:"glibc-2.12-1.209.0.1.el6")) flag++;
if (rpm_check(release:"OVS3.3", reference:"glibc-common-2.12-1.209.0.1.el6")) flag++;
if (rpm_check(release:"OVS3.3", reference:"nscd-2.12-1.209.0.1.el6")) flag++;

if (rpm_check(release:"OVS3.4", reference:"glibc-2.12-1.209.0.1.el6")) flag++;
if (rpm_check(release:"OVS3.4", reference:"glibc-common-2.12-1.209.0.1.el6")) flag++;
if (rpm_check(release:"OVS3.4", reference:"glibc-devel-2.12-1.209.0.1.el6")) flag++;
if (rpm_check(release:"OVS3.4", reference:"glibc-headers-2.12-1.209.0.1.el6")) flag++;
if (rpm_check(release:"OVS3.4", reference:"nscd-2.12-1.209.0.1.el6")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc / glibc-common / glibc-devel / glibc-headers / nscd");
}
