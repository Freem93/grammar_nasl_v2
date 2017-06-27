#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99823);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/05/04 13:21:27 $");

  script_cve_id(
    "CVE-2015-8803",
    "CVE-2015-8804",
    "CVE-2015-8805",
    "CVE-2016-6489"
  );
  script_osvdb_id(
    134093,
    134094,
    134095,
    142565
  );

  script_name(english:"EulerOS 2.0 SP1 : nettle (EulerOS-SA-2016-1061)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the nettle packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - Nettle is a cryptographic library that is designed to
    fit easily in more or less any context: In crypto
    toolkits for object-oriented languages(C++, Python,
    Pike, ...), in applications like LSH or GNUPG, or even
    in kernel space.

  - Secure Fix(es):

  - The ecc_256_modp function in ecc-256.c in Nettle before
    3.2 does not properly handle carry propagation and
    produces incorrect output in its implementation of the
    P-256 NIST elliptic curve, which allows attackers to
    have unspecified impact via unknown vectors, a
    different vulnerability than
    CVE-2015-8805.(CVE-2015-8803)

  - x86_64/ecc-384-modp.asm in Nettle before 3.2 does not
    properly handle carry propagation and produces
    incorrect output in its implementation of the P-384
    NIST elliptic curve, which allows attackers to have
    unspecified impact via unknown vectors.(CVE-2015-8804)

  - The ecc_256_modq function in ecc-256.c in Nettle before
    3.2 does not properly handle carry propagation and
    produces incorrect output in its implementation of the
    P-256 NIST elliptic curve, which allows attackers to
    have unspecified impact via unknown vectors, a
    different vulnerability than
    CVE-2015-8803.(CVE-2015-8805)

  - It was found that nettle's RSA and DSA decryption code
    was vulnerable to cache-related side channel attacks.
    An attacker could use this flaw to recover the private
    key from a co-located virtual-machine
    instance.(CVE-2016-6489)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # http://developer.huawei.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2016-1061
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3dcf8a5b");
  script_set_attribute(attribute:"solution", value:
"Update the affected nettle packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nettle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nettle-devel");
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

pkgs = ["nettle-2.7.1-8",
        "nettle-devel-2.7.1-8"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nettle");
}
