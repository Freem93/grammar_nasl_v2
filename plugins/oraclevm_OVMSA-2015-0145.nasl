#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2015-0145.
#

include("compat.inc");

if (description)
{
  script_id(86782);
  script_version("$Revision: 2.10 $");
  script_cvs_date("$Date: 2017/02/14 17:16:24 $");

  script_cve_id("CVE-2015-7181", "CVE-2015-7182", "CVE-2015-7183");
  script_osvdb_id(129797, 129798, 129799);

  script_name(english:"OracleVM 3.3 : nss / nss-util,nspr (OVMSA-2015-0145)");
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

nspr

  - Resolves: Bug 1269360 - (CVE-2015-7183)

  - nspr: heap-buffer overflow in PL_ARENA_ALLOCATE can lead
    to crash (under ASAN), potential memory corruption

nss

  - Added nss-vendor.patch to change vendor

  - Rebuild against updated NSPR

  - Sync up with the rhel-6.6 branch

  - Resolves: Bug 1224450

nss-util

  - Resolves: Bug 1269355 - CVE-2015-7182 (CVE-2015-7181)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2015-November/000376.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?999c4621"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:nss-util");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"OVS3.3", reference:"nspr-4.10.8-2.el6_7")) flag++;
if (rpm_check(release:"OVS3.3", reference:"nss-3.19.1-5.0.1.el6_7")) flag++;
if (rpm_check(release:"OVS3.3", reference:"nss-sysinit-3.19.1-5.0.1.el6_7")) flag++;
if (rpm_check(release:"OVS3.3", reference:"nss-tools-3.19.1-5.0.1.el6_7")) flag++;
if (rpm_check(release:"OVS3.3", reference:"nss-util-3.19.1-2.el6_7")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nspr / nss / nss-sysinit / nss-tools / nss-util");
}
