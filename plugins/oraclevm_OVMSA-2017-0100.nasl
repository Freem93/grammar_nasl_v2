#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2017-0100.
#

include("compat.inc");

if (description)
{
  script_id(100090);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/05/11 15:29:11 $");

  script_cve_id("CVE-2016-8864", "CVE-2016-9147", "CVE-2017-3136", "CVE-2017-3137");
  script_osvdb_id(146549, 149960, 155529, 155530);
  script_xref(name:"IAVA", value:"2017-A-0120");

  script_name(english:"OracleVM 3.3 / 3.4 : bind (OVMSA-2017-0100)");
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

  - Fix DNSKEY that encountered a CNAME (#1447869, ISC
    change 3391)

  - Fix CVE-2017-3136 (ISC change 4575)

  - Fix CVE-2017-3137 (ISC change 4578)

  - Fix and test caching CNAME before DNAME (ISC change
    4558)

  - Fix CVE-2016-9147 (ISC change 4510)

  - Fix regression introduced by CVE-2016-8864 (ISC change
    4530)

  - Restore SELinux contexts before named restart

  - Use /lib or /lib64 only if directory in chroot already
    exists

  - Tighten NSS library pattern, escape chroot mount path

  - Fix (CVE-2016-8864)

  - Do not change lib permissions in chroot (#1321239)

  - Support WKS records in chroot (#1297562)

  - Do not include patch backup in docs (fixes #1325081
    patch)

  - Backported relevant parts of [RT #39567] (#1259923)

  - Increase ISC_SOCKET_MAXEVENTS to 2048 (#1326283)

  - Fix multiple realms in nsupdate script like upstream
    (#1313286)

  - Fix multiple realm in nsupdate script (#1313286)

  - Use resolver-query-timeout high enough to recover all
    forwarders (#1325081)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2017-May/000692.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2017-May/000693.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected bind-libs / bind-utils packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:bind-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/10");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (rpm_check(release:"OVS3.3", reference:"bind-libs-9.8.2-0.62.rc1.el6_9.2")) flag++;
if (rpm_check(release:"OVS3.3", reference:"bind-utils-9.8.2-0.62.rc1.el6_9.2")) flag++;

if (rpm_check(release:"OVS3.4", reference:"bind-libs-9.8.2-0.62.rc1.el6_9.2")) flag++;
if (rpm_check(release:"OVS3.4", reference:"bind-utils-9.8.2-0.62.rc1.el6_9.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind-libs / bind-utils");
}
