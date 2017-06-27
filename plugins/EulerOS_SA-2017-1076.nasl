#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99942);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/05/22 13:36:33 $");

  script_cve_id(
    "CVE-2017-5461"
  );
  script_osvdb_id(
    155952
  );

  script_name(english:"EulerOS 2.0 SP2 : nss
nss-util (EulerOS-SA-2017-1076)");
  script_summary(english:"Checks the rpm output for the updated package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the version of the nss nss-util packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerability :

  - An out-of-bounds write flaw was found in the way NSS
    performed certain Base64-decoding operations. An
    attacker could use this flaw to create a specially
    crafted certificate which, when parsed by NSS, could
    cause it to crash or execute arbitrary code, using the
    permissions of the user running an application compiled
    against the NSS library. (CVE-2017-5461)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # http://developer.huawei.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1076
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?67c1fb4a");
  script_set_attribute(attribute:"solution", value:
"Update the affected nss
nss-util package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nss-devel");
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
if (isnull(sp) || sp !~ "^(2)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2");

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);

flag = 0;

pkgs = ["nss-3.28.4-1.0.0.1",
        "nss-devel-3.28.4-1.0.0.1",
        "nss-sysinit-3.28.4-1.0.0.1",
        "nss-tools-3.28.4-1.0.0.1",
        "nss-util-3.28.4-1.0",
        "nss-util-devel-3.28.4-1.0"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"2", reference:pkg)) flag++;

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
nss-util");
}
