#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2014-0033.
#

include("compat.inc");

if (description)
{
  script_id(79548);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/02/14 17:16:23 $");

  script_cve_id("CVE-2013-4237", "CVE-2013-4458", "CVE-2014-0475", "CVE-2014-5119");
  script_bugtraq_id(61729, 63299, 68505, 68983, 69738);
  script_osvdb_id(96318, 98836, 108943, 109188);

  script_name(english:"OracleVM 3.3 : glibc (OVMSA-2014-0033)");
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

  - Switch gettimeofday from INTUSE to libc_hidden_proto
    (#1099025).

  - Fix stack overflow due to large AF_INET6 requests
    (CVE-2013-4458, #1111460).

  - Fix buffer overflow in readdir_r (CVE-2013-4237,
    #1111460).

  - Fix memory order when reading libgcc handle (#905941).

  - Fix format specifier in malloc_info output (#1027261).

  - Fix nscd lookup for innetgr when netgroup has wildcards
    (#1054846).

  - Add mmap usage to malloc_info output (#1027261).

  - Use NSS_STATUS_TRYAGAIN to indicate insufficient buffer
    (#1087833).

  - [ppc] Add VDSO IFUNC for gettimeofday (#1028285).

  - [ppc] Fix ftime gettimeofday internal call returning
    bogus data (#1099025).

  - Also relocate in dependency order when doing symbol
    dependency testing (#1019916).

  - Fix infinite loop in nscd when netgroup is empty
    (#1085273).

  - Provide correct buffer length to netgroup queries in
    nscd (#1074342).

  - Return NULL for wildcard values in getnetgrent from nscd
    (#1085289).

  - Avoid overlapping addresses to stpcpy calls in nscd
    (#1082379).

  - Initialize all of datahead structure in nscd (#1074353).

  - Return EAI_AGAIN for AF_UNSPEC when herrno is TRY_AGAIN
    (#1044628).

  - Do not fail if one of the two responses to AF_UNSPEC
    fails (#845218).

  - nscd: Make SELinux checks dynamic (#1025933).

  - Fix race in free of fastbin chunk (#1027101).

  - Fix copy relocations handling of unique objects
    (#1032628).

  - Fix encoding name for IDN in getaddrinfo (#981942).

  - Fix return code from getent netgroup when the netgroup
    is not found (#1039988).

  - Fix handling of static TLS in dlopen'ed objects
    (#995972).

  - Don't use alloca in addgetnetgrentX (#1043557).

  - Adjust pointers to triplets in netgroup query data
    (#1043557)."
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2014-November/000229.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bed5f80b"
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

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/04");
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
if (rpm_check(release:"OVS3.3", reference:"glibc-2.12-1.149.el6")) flag++;
if (rpm_check(release:"OVS3.3", reference:"glibc-common-2.12-1.149.el6")) flag++;
if (rpm_check(release:"OVS3.3", reference:"nscd-2.12-1.149.el6")) flag++;

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
