#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85382);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/04/05 13:27:12 $");

  script_cve_id(
    "CVE-2015-5600",
    "CVE-2015-6563",
    "CVE-2015-6564",
    "CVE-2015-6565"
  );
  script_bugtraq_id(75990, 76317, 76497);
  script_osvdb_id(
    124938,
    126030,
    126031,
    126033
  );
  script_xref(name:"EDB-ID", value:"41173");

  script_name(english:"OpenSSH < 7.0 Multiple Vulnerabilities");
  script_summary(english:"Checks the OpenSSH banner version.");

  script_set_attribute(attribute:"synopsis", value:
"The SSH server running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of OpenSSH running on the remote
host is prior to 7.0. It is, therefore, affected by the following
vulnerabilities :

  - A security bypass vulnerability exists in the
    kbdint_next_device() function in file auth2-chall.c that
    allows the circumvention of MaxAuthTries during
    keyboard-interactive authentication. A remote attacker
    can exploit this issue to force the same authentication
    method to be tried thousands of times in a single pass
    by using a crafted keyboard-interactive 'devices'
    string, thus allowing a brute-force attack or causing a
    denial of service. (CVE-2015-5600)

  - A security bypass vulnerability exists in sshd due to
    improper handling of username data in
    MONITOR_REQ_PAM_INIT_CTX requests. A local attacker can
    exploit this, by sending a MONITOR_REQ_PWNAM request, to
    conduct an impersonation attack. Note that this issue
    only affects Portable OpenSSH. (CVE-2015-6563)

  - A privilege escalation vulnerability exists due to a
    use-after-free error in sshd that is triggered when
    handling a MONITOR_REQ_PAM_FREE_CTX request. A local
    attacker can exploit this to gain elevated privileges.
    Note that this issue only affects Portable OpenSSH.
    (CVE-2015-6564)

  - A local command execution vulnerability exists in sshd
    due to setting insecure world-writable permissions for
    TTYs. A local attacker can exploit this, by injecting
    crafted terminal escape sequences, to execute commands
    for logged-in users. (CVE-2015-6565)");
  script_set_attribute(attribute:"see_also", value:"http://www.openssh.com/txt/release-7.0");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSH 7.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/13");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/ssh");

  exit(0);
}

include("audit.inc");
include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");

# Ensure the port is open.
port = get_service(svc:"ssh", exit_on_fail:TRUE);

# Get banner for service.
banner = get_kb_item_or_exit("SSH/banner/"+port);

bp_banner = tolower(get_backport_banner(banner:banner));
if ("openssh" >!< bp_banner) audit(AUDIT_NOT_LISTEN, "OpenSSH", port);
if (report_paranoia < 2) audit(AUDIT_PARANOID);
if (backported) audit(code:0, AUDIT_BACKPORT_SERVICE, port, "OpenSSH");

# Check the version in the backported banner.
match = eregmatch(string:bp_banner, pattern:"openssh[-_]([0-9][-._0-9a-z]+)");
if (isnull(match)) audit(AUDIT_SERVICE_VER_FAIL, "OpenSSH", port);
version = match[1];

# Affected : < 7.0
if (
  version =~ "^[0-6]\."
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + banner +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 7.0\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "OpenSSH", port, version);
