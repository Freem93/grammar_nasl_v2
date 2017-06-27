#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2016-0013.
#

include("compat.inc");

if (description)
{
  script_id(88783);
  script_version("$Revision: 2.22 $");
  script_cvs_date("$Date: 2017/02/17 16:18:34 $");

  script_cve_id("CVE-2013-7423", "CVE-2014-6040", "CVE-2014-7817", "CVE-2015-0235", "CVE-2015-1781", "CVE-2015-7547");
  script_bugtraq_id(69472, 71216, 72325, 72844, 74255);
  script_osvdb_id(110668, 110669, 110670, 110671, 110672, 110673, 110675, 115032, 117579, 117751, 121105, 134584);
  script_xref(name:"TRA", value:"TRA-2017-08");
  script_xref(name:"IAVA", value:"2016-A-0053");

  script_name(english:"OracleVM 3.3 : glibc (OVMSA-2016-0013) (GHOST)");
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

  - Update fix for CVE-2015-7547 (#1296028).

  - Create helper threads with enough stack for POSIX AIO
    and timers (#1301625).

  - Fix CVE-2015-7547: getaddrinfo stack-based buffer
    overflow (#1296028).

  - Support loading more libraries with static TLS
    (#1291270).

  - Check for NULL arena pointer in _int_pvalloc (#1256890).

  - Don't change no_dyn_threshold on mallopt failure
    (#1256891).

  - Unlock main arena after allocation in calloc (#1256812).

  - Enable robust malloc change again (#1256812).

  - Fix perturbing in malloc on free and simply perturb_byte
    (#1256812).

  - Don't fall back to mmap prematurely (#1256812).

  - The malloc deadlock avoidance support has been
    temporarily removed since it triggers deadlocks in
    certain applications (#1244002).

  - Fix ruserok check to reject, not skip, negative user
    checks (#1217186).

  - Optimize ruserok function for large ~/.rhosts
    (#1217186).

  - Fix crash in valloc due to the backtrace deadlock fix
    (#1207236).

  - Fix buffer overflow in gethostbyname_r with misaligned
    buffer (#1209376, CVE-2015-1781).

  - Avoid deadlock in malloc on backtrace (#1066724).

  - Support running applications that use Intel AVX-512
    (#1195453).

  - Silence logging of record type mismatch for DNSSEC
    records (#1088301).

  - Shrink heap on free when vm.overcommit_memory == 2
    (#867679).

  - Enhance nscd to detect any configuration file changes
    (#859965).

  - Fix __times handling of EFAULT when buf is NULL
    (#1124204).

  - Fix memory leak with dlopen and thread-local storage
    variables (#978098).

  - Prevent getaddrinfo from writing DNS queries to random
    fd (CVE-2013-7423, - Implement userspace half of in6.h
    header coordination (#1053178).

  - Correctely size relocation cache used by profiler
    (#1144132).

  - Fix reuse of cached stack leading to bounds overrun of
    DTV (#1116050).

  - Return failure in getnetgrent only when all netgroups
    have been searched (#1085312).

  - Fix valgrind warning in nscd_stats (#1091915).

  - Initialize xports array (#1159167).

  - Fix tst-default-attr test to not fail on powerpc
    (#1023306).

  - Fix parsing of numeric hosts in gethostbyname_r
    (CVE-2015-0235, #1183534).

  - Fix typo in nscd/selinux.c (#1125307).

  - Actually run test-iconv modules (#1176907).

  - Fix recursive dlopen (#1154563).

  - Fix crashes on invalid input in IBM gconv modules
    (CVE-2014-6040, #1172044).

  - Fix wordexp to honour WRDE_NOCMD (CVE-2014-7817,
    #1171296).

  - Fix typo in res_send and res_query (#rh1138769)."
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2016-February/000418.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?92d5b0bd"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2017-08"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected glibc / glibc-common / nscd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Exim GHOST (glibc gethostbyname) Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/16");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/17");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"OVS3.3", reference:"glibc-2.12-1.166.el6_7.7")) flag++;
if (rpm_check(release:"OVS3.3", reference:"glibc-common-2.12-1.166.el6_7.7")) flag++;
if (rpm_check(release:"OVS3.3", reference:"nscd-2.12-1.166.el6_7.7")) flag++;

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
