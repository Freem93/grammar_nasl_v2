#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99938);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/03 13:42:52 $");

  script_cve_id(
    "CVE-2016-8650",
    "CVE-2016-9793",
    "CVE-2017-2618",
    "CVE-2017-6951"
  );
  script_osvdb_id(
    147818,
    148409,
    152205,
    153884
  );

  script_name(english:"EulerOS 2.0 SP2 : kernel (EulerOS-SA-2017-1072)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - A flaw was found in the Linux kernel key management
    subsystem in which a local attacker could crash the
    kernel or corrupt the stack and additional memory
    (denial of service) by supplying a specially crafted
    RSA key. This flaw panics the machine during the
    verification of the RSA key. (CVE-2016-8650)

  - A flaw was found in the Linux kernel's implementation
    of setsockopt for the SO_{SND|RCV}BUFFORCE setsockopt()
    system call. Users with non-namespace CAP_NET_ADMIN are
    able to trigger this call and create a situation in
    which the sockets sendbuff data size could be negative.
    This could adversely affect memory allocations and
    create situations where the system could crash or cause
    memory corruption. (CVE-2016-9793)

  - A flaw was found in the Linux kernel's handling of
    clearing SELinux attributes on /proc/pid/attr files. An
    empty (null) write to this file can crash the system by
    causing the system to attempt to access unmapped kernel
    memory. (CVE-2017-2618)

  - The keyring_search_aux function in
    security/keys/keyring.c in the Linux kernel through
    3.14.79 allows local users to cause a denial of service
    (NULL pointer dereference and OOPS) via a request_key
    system call for the 'dead' type.(CVE-2017-6951)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # http://developer.huawei.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1072
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?96f2acf8");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
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

pkgs = ["kernel-3.10.0-327.49.58.45",
        "kernel-debug-3.10.0-327.49.58.45",
        "kernel-debug-devel-3.10.0-327.49.58.45",
        "kernel-debuginfo-3.10.0-327.49.58.45",
        "kernel-debuginfo-common-x86_64-3.10.0-327.49.58.45",
        "kernel-devel-3.10.0-327.49.58.45",
        "kernel-headers-3.10.0-327.49.58.45",
        "kernel-tools-3.10.0-327.49.58.45",
        "kernel-tools-libs-3.10.0-327.49.58.45",
        "perf-3.10.0-327.49.58.45",
        "python-perf-3.10.0-327.49.58.45"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
