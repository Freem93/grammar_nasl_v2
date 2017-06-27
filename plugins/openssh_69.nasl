#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84638);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/07/10 14:11:56 $");

  script_cve_id("CVE-2015-5352");
  script_bugtraq_id(75525);
  script_osvdb_id(124008, 124019);

  script_name(english:"OpenSSH < 6.9 Multiple Vulnerabilities");
  script_summary(english:"Checks the OpenSSH banner version.");

  script_set_attribute(attribute:"synopsis", value:
"The SSH server running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of OpenSSH running on the remote
host is prior to 6.9. It is, therefore, affected by the following
vulnerabilities :

  - A flaw exists within the x11_open_helper() function in
    the 'channels.c' file that allows connections to be
    permitted after 'ForwardX11Timeout' has expired. A
    remote attacker can exploit this to bypass timeout
    checks and XSECURITY restrictions. (CVE-2015-5352)

  - Various issues were addressed by fixing the weakness in
    agent locking by increasing the failure delay, storing
    the salted hash of the password, and using a timing-safe
    comparison function.

  - An out-of-bounds read error exists when handling
    incorrect pattern lengths. A remote attacker can exploit
    this to cause a denial of service or disclose sensitive
    information in the memory.

  - An out-of-bounds read error exists when parsing the
    'EscapeChar' configuration option.");
  script_set_attribute(attribute:"see_also", value:"http://www.openssh.com/txt/release-6.9");
  # https://anongit.mindrot.org/openssh.git/commit/?id=77199d6ec8986d470487e66f8ea8f4cf43d2e20c
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?725c4682");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSH 6.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/09");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

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
if (backported) audit(code:0, AUDIT_BACKPORT_SERVICE, port, "OpenSSH");

# Check the version in the backported banner.
match = eregmatch(string:bp_banner, pattern:"openssh[-_]([0-9][-._0-9a-z]+)");
if (isnull(match)) audit(AUDIT_SERVICE_VER_FAIL, "OpenSSH", port);
version = match[1];

# Does not affect all configurations
if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Affected : < 6.9
if (
  version =~ "^[0-5]\." ||
  version =~ "^6\.[0-8]($|[^0-9])"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + banner +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 6.9\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "OpenSSH", port, version);
