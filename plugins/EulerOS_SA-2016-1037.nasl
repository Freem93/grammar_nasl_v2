#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99800);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/05/04 13:21:27 $");

  script_cve_id(
    "CVE-2014-3477",
    "CVE-2014-3532",
    "CVE-2014-3533",
    "CVE-2014-3635",
    "CVE-2014-3636",
    "CVE-2014-3637",
    "CVE-2014-3638",
    "CVE-2014-3639",
    "CVE-2014-7824",
    "CVE-2015-0245"
  );
  script_bugtraq_id(
    67986,
    68337,
    68339,
    69829,
    69831,
    69832,
    69833,
    69834,
    71012,
    72545
  );
  script_osvdb_id(
    108033,
    108619,
    108620,
    111638,
    111639,
    111640,
    111641,
    111642,
    118407
  );

  script_name(english:"EulerOS 2.0 SP1 : dbus (EulerOS-SA-2016-1037)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the dbus packages installed, the EulerOS
installation on the remote host is affected by the following
vulnerabilities :

  - D-BUS is a system for sending messages between
    applications. It is used both for the system-wide
    message bus service, and as a per-user-login-session
    messaging facility.

  - Security Fix(es)

  - dbus 1.3.0 before 1.6.22 and 1.8.x before 1.8.6, when
    running on Linux 2.6.37-rc4 or later, allows local
    users to cause a denial of service (system-bus
    disconnect of other services or applications) by
    sending a message containing a file descriptor, then
    exceeding the maximum recursion depth before the
    initial message is forwarded.(CVE-2014-3532)

  - dbus 1.3.0 before 1.6.22 and 1.8.x before 1.8.6 allows
    local users to cause a denial of service (disconnect)
    via a certain sequence of crafted messages that cause
    the dbus-daemon to forward a message containing an
    invalid file descriptor.(CVE-2014-3533)

  - D-Bus 1.4.x through 1.6.x before 1.6.30, 1.8.x before
    1.8.16, and 1.9.x before 1.9.10 does not validate the
    source of ActivationFailure signals, which allows local
    users to cause a denial of service (activation failure
    error returned) by leveraging a race condition
    involving sending an ActivationFailure signal before
    systemd responds.(CVE-2015-0245)

  - D-Bus 1.3.0 through 1.6.x before 1.6.24 and 1.8.x
    before 1.8.8 allows local users to (1) cause a denial
    of service (prevention of new connections and
    connection drop) by queuing the maximum number of file
    descriptors or (2) cause a denial of service
    (disconnect) via multiple messages that combine to have
    more than the allowed number of file descriptors for a
    single sendmsg call.(CVE-2014-3636)

  - The dbus-daemon in D-Bus 1.2.x through 1.4.x, 1.6.x
    before 1.6.20, and 1.8.x before 1.8.4, sends an
    AccessDenied error to the service instead of a client
    when the client is prohibited from accessing the
    service, which allows local users to cause a denial of
    service (initialization failure and exit) or possibly
    conduct a side-channel attack via a D-Bus message to an
    inactive service.(CVE-2014-3477)

  - D-Bus 1.3.0 through 1.6.x before 1.6.24 and 1.8.x
    before 1.8.8 does not properly close connections for
    processes that have terminated, which allows local
    users to cause a denial of service via a D-bus message
    containing a D-Bus connection file
    descriptor.(CVE-2014-3637)

  - Off-by-one error in D-Bus 1.3.0 through 1.6.x before
    1.6.24 and 1.8.x before 1.8.8, when running on a 64-bit
    system and the max_message_unix_fds limit is set to an
    odd number, allows local users to cause a denial of
    service (dbus-daemon crash) or possibly execute
    arbitrary code by sending one more file descriptor than
    the limit, which triggers a heap-based buffer overflow
    or an assertion failure.(CVE-2014-3635)

  - The bus_connections_check_reply function in
    config-parser.c in D-Bus before 1.6.24 and 1.8.x before
    1.8.8 allows local users to cause a denial of service
    (CPU consumption) via a large number of method
    calls.(CVE-2014-3638)

  - The dbus-daemon in D-Bus before 1.6.24 and 1.8.x before
    1.8.8 does not properly close old connections, which
    allows local users to cause a denial of service
    (incomplete connection consumption and prevention of
    new connections) via a large number of incomplete
    connections.(CVE-2014-3639)

  - D-Bus 1.3.0 through 1.6.x before 1.6.26, 1.8.x before
    1.8.10, and 1.9.x before 1.9.2 allows local users to
    cause a denial of service (prevention of new
    connections and connection drop) by queuing the maximum
    number of file descriptors. NOTE: this vulnerability
    exists because of an incomplete fix for
    CVE-2014-3636.1.(CVE-2014-7824)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # http://developer.huawei.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2016-1037
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1b71aa3d");
  script_set_attribute(attribute:"solution", value:
"Update the affected dbus packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:dbus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:dbus-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:dbus-x11");
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

pkgs = ["dbus-1.6.12-11.h10",
        "dbus-devel-1.6.12-11.h10",
        "dbus-libs-1.6.12-11.h10",
        "dbus-x11-1.6.12-11.h10"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"1", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dbus");
}
