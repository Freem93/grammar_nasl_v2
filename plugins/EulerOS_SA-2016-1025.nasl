#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99788);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/05/23 14:39:44 $");

  script_cve_id(
    "CVE-2016-4051",
    "CVE-2016-4052",
    "CVE-2016-4053",
    "CVE-2016-4054",
    "CVE-2016-4553",
    "CVE-2016-4554",
    "CVE-2016-4555",
    "CVE-2016-4556"
  );
  script_osvdb_id(
    137402,
    137403,
    137404,
    137405,
    138132,
    138133,
    138134
  );

  script_name(english:"EulerOS 2.0 SP1 : squid (EulerOS-SA-2016-1025)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the squid package installed, the EulerOS
installation on the remote host is affected by the following
vulnerabilities :

  - A buffer overflow flaw was found in the way the Squid
    cachemgr.cgi utility processed remotely relayed Squid
    input. When the CGI interface utility is used, a remote
    attacker could possibly use this flaw to execute
    arbitrary code. (CVE-2016-4051)

  - Buffer overflow and input validation flaws were found
    in the way Squid processed ESI responses. If Squid was
    used as a reverse proxy, or for TLS/HTTPS interception,
    a remote attacker able to control ESI components on an
    HTTP server could use these flaws to crash Squid,
    disclose parts of the stack memory, or possibly execute
    arbitrary code as the user running Squid.
    (CVE-2016-4052, CVE-2016-4053, CVE-2016-4054)

  - An input validation flaw was found in the way Squid
    handled intercepted HTTP Request messages. An attacker
    could use this flaw to bypass the protection against
    issues related to CVE-2009-0801, and perform cache
    poisoning attacks on Squid. (CVE-2016-4553)

  - An input validation flaw was found in Squid's
    mime_get_header_field() function, which is used to
    search for headers within HTTP requests. An attacker
    could send an HTTP request from the client side with
    specially crafted header Host header that bypasses
    same-origin security protections, causing Squid
    operating as interception or reverse-proxy to contact
    the wrong origin server. It could also be used for
    cache poisoning for client not following RFC 7230.
    (CVE-2016-4554)

  - A NULL pointer dereference flaw was found in the way
    Squid processes ESI responses. If Squid was used as a
    reverse proxy or for TLS/HTTPS interception, a
    malicious server could use this flaw to crash the Squid
    worker process. (CVE-2016-4555)

  - An incorrect reference counting flaw was found in the
    way Squid processes ESI responses. If Squid is
    configured as reverse-proxy, for TLS/HTTPS
    interception, an attacker controlling a server accessed
    by Squid, could crash the squid worker, causing a
    Denial of Service attack. (CVE-2016-4556)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # http://developer.huawei.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2016-1025
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8d5211c6");
  script_set_attribute(attribute:"solution", value:
"Update the affected squid packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:squid");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/01");
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

pkgs = ["squid-3.3.8-26.4"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "squid");
}
