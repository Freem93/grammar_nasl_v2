#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99822);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/05/04 13:21:27 $");

  script_cve_id(
    "CVE-2015-5194",
    "CVE-2015-5195",
    "CVE-2015-5196",
    "CVE-2015-5219",
    "CVE-2015-7691",
    "CVE-2015-7692",
    "CVE-2015-7701",
    "CVE-2015-7702",
    "CVE-2015-7703",
    "CVE-2015-7852",
    "CVE-2015-7974",
    "CVE-2015-7977",
    "CVE-2015-7978",
    "CVE-2015-7979",
    "CVE-2015-8158"
  );
  script_osvdb_id(
    116071,
    126663,
    126664,
    126665,
    126666,
    129302,
    129307,
    129308,
    129311,
    133378,
    133382,
    133384,
    133387,
    133391
  );

  script_name(english:"EulerOS 2.0 SP1 : ntp (EulerOS-SA-2016-1060)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the ntp packages installed, the EulerOS
installation on the remote host is affected by the following
vulnerabilities :

  - It was found that ntpd could crash due to an
    uninitialized variable when processing malformed
    logconfig configuration commands.(CVE-2015-5194)

  - It was found that ntpd would exit with a segmentation
    fault when a statistics type that was not enabled
    during compilation (e.g. timingstats) was referenced by
    the statistics or filegen configuration
    command.(CVE-2015-5195)

  - It was found that NTP's :config command could be used
    to set the pidfile and driftfile paths without any
    restrictions. A remote attacker could use this flaw to
    overwrite a file on the file system with a file
    containing the pid of the ntpd process (immediately) or
    the current estimated drift of the system clock (in
    hourly intervals).(CVE-2015-5196)

  - It was discovered that the sntp utility could become
    unresponsive due to being caught in an infinite loop
    when processing a crafted NTP packet.(CVE-2015-5219)

  - It was found that the fix for CVE-2014-9750 was
    incomplete: three issues were found in the value length
    checks in NTP's ntp_crypto.c, where a packet with
    particular autokey operations that contained malicious
    data was not always being completely validated. A
    remote attacker could use a specially crafted NTP
    packet to crash ntpd.(CVE-2015-7691)

  - It was found that the fix for CVE-2014-9750 was
    incomplete: three issues were found in the value length
    checks in NTP's ntp_crypto.c, where a packet with
    particular autokey operations that contained malicious
    data was not always being completely validated. A
    remote attacker could use a specially crafted NTP
    packet to crash ntpd.(CVE-2015-7692)

  - A memory leak flaw was found in ntpd's CRYPTO_ASSOC. If
    ntpd was configured to use autokey authentication, an
    attacker could send packets to ntpd that would, after
    several days of ongoing attack, cause it to run out of
    memory.(CVE-2015-7701)

  - It was found that the fix for CVE-2014-9750 was
    incomplete: three issues were found in the value length
    checks in NTP's ntp_crypto.c, where a packet with
    particular autokey operations that contained malicious
    data was not always being completely validated. A
    remote attacker could use a specially crafted NTP
    packet to crash ntpd.(CVE-2015-7702)

  - It was found that NTP's :config command could be used
    to set the pidfile and driftfile paths without any
    restrictions. A remote attacker could use this flaw to
    overwrite a file on the file system with a file
    containing the pid of the ntpd process (immediately) or
    the current estimated drift of the system clock (in
    hourly intervals).(CVE-2015-7703)

  - An off-by-one flaw, leading to a buffer overflow, was
    found in cookedprint functionality of ntpq. A specially
    crafted NTP packet could potentially cause ntpq to
    crash.(CVE-2015-7852)

  - A flaw was found in the way NTP verified trusted keys
    during symmetric key authentication. An authenticated
    client (A) could use this flaw to modify a packet sent
    between a server (B) and a client (C) using a key that
    is different from the one known to the client
    (A).(CVE-2015-7974)

  - A NULL pointer dereference flaw was found in the way
    ntpd processed 'ntpdc reslist' commands that queried
    restriction lists with a large amount of entries. A
    remote attacker could potentially use this flaw to
    crash ntpd.(CVE-2015-7977)

  - A stack-based buffer overflow flaw was found in the way
    ntpd processed 'ntpdc reslist' commands that queried
    restriction lists with a large amount of entries. A
    remote attacker could use this flaw to crash
    ntpd.(CVE-2015-7978)

  - It was found that when NTP was configured in broadcast
    mode, a remote attacker could broadcast packets with
    bad authentication to all clients. The clients, upon
    receiving the malformed packets, would break the
    association with the broadcast server, causing them to
    become out of sync over a longer period of
    time.(CVE-2015-7979)

  - A flaw was found in the way the ntpq client processed
    certain incoming packets in a loop in the getresponse()
    function. A remote attacker could potentially use this
    flaw to crash an ntpq client instance.(CVE-2015-8158)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # http://developer.huawei.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2016-1060
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?518aa2d6");
  script_set_attribute(attribute:"solution", value:
"Update the affected ntp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ntpdate");
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

pkgs = ["ntp-4.2.6p5-25.0.1.h1",
        "ntpdate-4.2.6p5-25.0.1.h1"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ntp");
}
