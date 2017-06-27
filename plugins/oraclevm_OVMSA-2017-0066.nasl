#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2017-0066.
#

include("compat.inc");

if (description)
{
  script_id(99569);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/04/24 13:52:13 $");

  script_cve_id("CVE-2006-4095", "CVE-2007-2241", "CVE-2007-2925", "CVE-2007-2926", "CVE-2007-6283", "CVE-2008-0122", "CVE-2008-1447", "CVE-2009-0025", "CVE-2009-0696", "CVE-2010-0097", "CVE-2010-0290", "CVE-2011-0414", "CVE-2011-1910", "CVE-2011-2464", "CVE-2012-1033", "CVE-2012-1667", "CVE-2012-3817", "CVE-2012-4244", "CVE-2012-5166", "CVE-2012-5688", "CVE-2012-5689", "CVE-2013-2266", "CVE-2013-4854", "CVE-2014-0591", "CVE-2014-8500", "CVE-2015-1349", "CVE-2015-4620", "CVE-2015-5477", "CVE-2015-5722", "CVE-2015-8000", "CVE-2015-8704", "CVE-2016-1285", "CVE-2016-1286", "CVE-2016-2776", "CVE-2016-2848", "CVE-2016-8864", "CVE-2016-9147", "CVE-2017-3136", "CVE-2017-3137");
  script_bugtraq_id(19859, 25037, 27283, 30131, 33151, 35848, 37118, 37865, 46491, 48007, 48566, 51898, 53772, 54658, 55522, 55852, 56817, 57556, 58736, 61479, 64801, 71590, 72673, 75588);
  script_osvdb_id(36235, 40811, 41211, 46776, 48244, 51368, 53917, 56584, 61853, 73605, 78916, 82609, 84228, 85417, 86118, 88126, 89584, 91712, 95707, 101973, 115524, 118546, 124233, 125438, 126995, 131837, 133380, 135663, 135664, 144854, 146115, 146549, 147929, 149960, 155529, 155530);
  script_xref(name:"IAVA", value:"2008-A-0045");
  script_xref(name:"IAVA", value:"2017-A-0004");
  script_xref(name:"IAVA", value:"2017-A-0120");

  script_name(english:"OracleVM 3.3 / 3.4 : bind (OVMSA-2017-0066)");
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
    forwarders (#1325081)

  - Fix (CVE-2016-2848)

  - Fix infinite loop in start_lookup (#1306504)

  - Fix (CVE-2016-2776)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2017-April/000681.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cd826bc7"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2017-April/000680.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?67f77036"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected bind-libs / bind-utils packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:X/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(16, 189, 200, 287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:bind-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/21");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/24");
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
if (rpm_check(release:"OVS3.3", reference:"bind-libs-9.8.2-0.62.rc1.el6_9.1")) flag++;
if (rpm_check(release:"OVS3.3", reference:"bind-utils-9.8.2-0.62.rc1.el6_9.1")) flag++;

if (rpm_check(release:"OVS3.4", reference:"bind-libs-9.8.2-0.62.rc1.el6_9.1")) flag++;
if (rpm_check(release:"OVS3.4", reference:"bind-utils-9.8.2-0.62.rc1.el6_9.1")) flag++;

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
