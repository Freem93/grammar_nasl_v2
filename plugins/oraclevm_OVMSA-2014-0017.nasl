#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2014-0017.
#

include("compat.inc");

if (description)
{
  script_id(79539);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/02/14 17:16:23 $");

  script_cve_id("CVE-2013-0242", "CVE-2013-1914", "CVE-2014-0475", "CVE-2014-5119");
  script_bugtraq_id(57638, 58839, 68505, 68983, 69738);
  script_osvdb_id(89747, 92038, 108943, 109188);

  script_name(english:"OracleVM 3.3 : glibc (OVMSA-2014-0017)");
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

  - Remove gconv transliteration loadable modules support
    (CVE-2014-5119, - _nl_find_locale: Improve handling of
    crafted locale names (CVE-2014-0475, 

  - Don't use alloca in addgetnetgrentX (#1087789).

  - Adjust pointers to triplets in netgroup query data
    (#1087789).

  - Return EAI_AGAIN for AF_UNSPEC when herrno is TRY_AGAIN
    (#1098050).

  - Fix race in free of fastbin chunk (#1091162).

  - Revert the addition of gettimeofday vDSO function for
    ppc and ppc64 until OPD VDSO function call issues are
    resolved (#1026533).

  - Call gethostbyname4_r only for PF_UNSPEC (#1022022).

  - Fix integer overflows in *valloc and memalign.
    (#1008310).

  - Initialize res_hconf in nscd (#970090).

  - Update previous patch for dcigettext.c and loadmsgcat.c
    (#834386).

  - Save search paths before performing relro protection
    (#988931).

  - Correctly name the 240-bit slow path sytemtap probe
    slowpow_p10 for slowpow (#905575).

  - Align value of stacksize in nptl-init (#663641).

  - Renamed release engineering directory from 'fedora' to
    `releng' (#903754).

  - Backport GLIBC sched_getcpu and gettimeofday vDSO
    functions for ppc (#929302).

  - Fall back to local DNS if resolv.conf does not define
    nameservers (#928318).

  - Add systemtap probes to slowexp and slowpow (#905575).

  - Fix getaddrinfo stack overflow resulting in application
    crash (CVE-2013-1914, #951213).

  - Fix multibyte character processing crash in regexp
    (CVE-2013-0242, #951213).

  - Add netgroup cache support for nscd (#629823).

  - Fix multiple nss_compat initgroups bugs (#966778).

  - Don't use simple lookup for AF_INET when AI_CANONNAME is
    set (#863384).

  - Add MAP_HUGETLB and MAP_STACK support (#916986).

  - Update translation for stale file handle error
    (#970776).

  - Improve performance of _SC_NPROCESSORS_ONLN (#rh952422).

  - Fix up _init in pt-initfini to accept arguments
    (#663641).

  - Set reasonable limits on xdr requests to prevent memory
    leaks (#848748).

  - Fix mutex locking for PI mutexes on spurious wake-ups on
    pthread condvars (#552960).

  - New environment variable GLIBC_PTHREAD_STACKSIZE to set
    thread stack size (#663641).

  - Improved handling of recursive calls in backtrace
    (#868808).

  - The ttyname and ttyname_r functions on Linux now fall
    back to searching for the tty file descriptor in
    /dev/pts or /dev if /proc is not available. This allows
    creation of chroots without the procfs mounted on /proc.
    (#851470)

  - Don't free rpath strings allocated during startup until
    after ld.so is re-relocated. (#862094)

  - Consistantly MANGLE/DEMANGLE function pointers. Fix use
    after free in dcigettext.c (#834386).

  - Change rounding mode only when necessary (#966775).

  - Backport of code to allow incremental loading of library
    list (#886968).

  - Fix loading of audit libraries when TLS is in use
    (#919562)

  - Fix application of SIMD FP exception mask (#929388)."
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2014-September/000218.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2eb23e08"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected glibc / glibc-common / nscd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/26");
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
if (rpm_check(release:"OVS3.3", reference:"glibc-2.12-1.132.el6_5.4")) flag++;
if (rpm_check(release:"OVS3.3", reference:"glibc-common-2.12-1.132.el6_5.4")) flag++;
if (rpm_check(release:"OVS3.3", reference:"nscd-2.12-1.132.el6_5.4")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc / glibc-common / nscd");
}
