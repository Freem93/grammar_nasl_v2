#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2014-0082.
#

include("compat.inc");

if (description)
{
  script_id(80007);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/02/14 17:16:23 $");

  script_cve_id("CVE-2014-1568");
  script_bugtraq_id(70116, 72178);
  script_osvdb_id(112036);

  script_name(english:"OracleVM 3.3 : nss (OVMSA-2014-0082)");
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

nss

  - Added nss-vendor.patch to change vendor

  - Resolves: Bug 1158160 - Upgrade to NSS 3.16.2.3 for
    Firefox 31.3

  - Remove unused indentation pseudo patch

  - require nss util 3.16.2.3

  - Restore patch for certutil man page

  - supply missing options descriptions to the man page

  - Resolves: Bug 1158160 - Upgrade to NSS 3.16.2.3 for
    Firefox 31.3

  - Resolves: Bug 1165003 - Upgrade to NSS 3.16.2.3 for
    Firefox 31.3

  - Support TLS_FALLBACK_SCSV in tstclnt and ssltap

  - Resolves: Bug 1145432 - (CVE-2014-1568)

  - Fix pem deadlock caused by previous version of a fix for
    a race condition

  - Fixes: Bug 1090681

  - Add references to bugs filed upstream

  - Related: Bug 1090681, Bug 1104300

  - Resolves: Bug 1090681 - RHDS 9.1
    389-ds-base-1.2.11.15-31 crash in PK11_DoesMechanism

  - Replace expired PayPal test certificate that breaks the
    build

  - Related: Bug 1099619

  - Fix defects found by coverity

  - Resolves: Bug 1104300

  - Backport nss-3.12.6 upstream fix required by Firefox 31

  - Resolves: Bug 1099619

nss-util

  - Resolves: Bug 1165003 - Upgrade to NSS 3.16.2.3 for
    Firefox 31.3

  - Fix the required nspr version to be 4.10.6"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2014-December/000247.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b3d548e1"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:nss-util");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/15");
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
if (rpm_check(release:"OVS3.3", reference:"nss-3.16.2.3-3.0.1.el6_6")) flag++;
if (rpm_check(release:"OVS3.3", reference:"nss-sysinit-3.16.2.3-3.0.1.el6_6")) flag++;
if (rpm_check(release:"OVS3.3", reference:"nss-tools-3.16.2.3-3.0.1.el6_6")) flag++;
if (rpm_check(release:"OVS3.3", reference:"nss-util-3.16.2.3-2.el6_6")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nss / nss-sysinit / nss-tools / nss-util");
}
