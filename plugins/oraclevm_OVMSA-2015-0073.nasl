#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2015-0073.
#

include("compat.inc");

if (description)
{
  script_id(84440);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2017/02/14 17:16:24 $");

  script_name(english:"OracleVM 3.3 : nss (OVMSA-2015-0073)");
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

  - Additional NULL initialization.

  - Updated the patch to keep old cipher suite order

  - Resolves: Bug 1224449

  - Rebase to nss-3.19.1

  - Resolves: Bug 1224449

  - On RHEL 6.x keep the TLS version defaults unchanged.

  - Relax the requirement from pkcs11-devel to
    nss-softokn-freebl-devel to allow same or newer.

  - Require softokn build 22 to ensure runtime
    compatibility.

  - Update to CKBI 2.4 from NSS 3.18.1 (the only change in
    NSS 3.18.1)

  - Update and reeneable nss-646045.patch on account of the
    rebase

  - Resolves: Bug 1207052 - Rebase nss to 3.18 for Firefox
    38 ESR [RHEL7.1]

  - Fix shell syntax error in nss/tests/all.sh

  - Resolves: Bug 1207052 - Rebase nss to 3.18 for Firefox
    38 ESR [RHEL-6.6]

  - Restore a patch that had been mistakenly disabled

  - Resolves: Bug 1207052 - Rebase nss to 3.18 for Firefox
    38 ESR [RHEL-6.6]

  - Replace expired PayPal test certificate that breaks the
    build

  - Resolves: Bug 1207052 - Rebase nss to 3.18 for Firefox
    38 ESR [RHEL-6.6]

  - Rebase to NSS 3.18

  - Resolves: Bug 1200900 - Rebase nss to 3.18 for Firefox
    38 ESR [RHEL-6.6]

  - Keep the same cipher suite order as we had in
    NSS_3_15_3_RTM

  - Resolves: Bug 1202488 - openldap-2.4.23-34.el6_5.1.i686
    fails after updating nss to nss-3.16.1-4.el6_5.i686

  - Resolves: Bug 1182902 - rhel65 ns-slapd crash, segfault
    error 4 in libnss3.so in PK11_DoesMechanism at
    pk11slot.c:1824

nss-util

  - Rebase to nss-3.19.1

  - Resolves: Bug 1224449

  - Resolves: - Bug 1205064 - [RHEL6.6] nss-util 3.18 rebase
    required for firefox 38 ESR"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2015-June/000323.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:nss-util");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/29");
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
if (rpm_check(release:"OVS3.3", reference:"nss-3.19.1-3.0.1.el6_6")) flag++;
if (rpm_check(release:"OVS3.3", reference:"nss-sysinit-3.19.1-3.0.1.el6_6")) flag++;
if (rpm_check(release:"OVS3.3", reference:"nss-tools-3.19.1-3.0.1.el6_6")) flag++;
if (rpm_check(release:"OVS3.3", reference:"nss-util-3.19.1-1.el6_6")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nss / nss-sysinit / nss-tools / nss-util");
}
