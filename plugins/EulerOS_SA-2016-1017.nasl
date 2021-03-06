#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99780);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/05/04 13:21:26 $");

  script_cve_id(
    "CVE-2016-1978",
    "CVE-2016-1979"
  );
  script_osvdb_id(
    135604,
    135718
  );

  script_name(english:"EulerOS 2.0 SP1 : nss
nspr
nss-softokn
nss-util (EulerOS-SA-2016-1017)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the nss nspr nss-softokn nss-util
packages installed, the EulerOS installation on the remote host is
affected by the following vulnerabilities :

  - A use-after-free flaw was found in the way NSS handled
    DHE (Diffie-Hellman key exchange) and ECDHE (Elliptic
    Curve Diffie-Hellman key exchange) handshake messages.
    A remote attacker could send a specially crafted
    handshake message that, when parsed by an application
    linked against NSS, would cause that application to
    crash or, under certain special conditions, execute
    arbitrary code using the permissions of the user
    running the application.(CVE-2016-1978)

  - A use-after-free flaw was found in the way NSS
    processed certain DER (Distinguished Encoding Rules)
    encoded cryptographic keys. An attacker could use this
    flaw to create a specially crafted DER encoded
    certificate which, when parsed by an application
    compiled against the NSS library, could cause that
    application to crash, or execute arbitrary code using
    the permissions of the user running the application.
    (CVE-2016-1979)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # http://developer.huawei.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2016-1017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?45801c9e");
  script_set_attribute(attribute:"solution", value:
"Update the affected nss
nspr
nss-softokn
nss-util packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nss-softokn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nss-softokn-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nss-softokn-freebl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nss-softokn-freebl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nss-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nss-util-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(1)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP1");

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);

flag = 0;

pkgs = ["nspr-4.11.0-1",
        "nspr-devel-4.11.0-1",
        "nss-3.21.0-9",
        "nss-devel-3.21.0-9",
        "nss-softokn-3.16.2.3-14.2",
        "nss-softokn-devel-3.16.2.3-14.2",
        "nss-softokn-freebl-3.16.2.3-14.2",
        "nss-softokn-freebl-devel-3.16.2.3-14.2",
        "nss-sysinit-3.21.0-9",
        "nss-tools-3.21.0-9",
        "nss-util-3.21.0-2.2",
        "nss-util-devel-3.21.0-2.2"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"1", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nss
nspr
nss-softokn
nss-util");
}
