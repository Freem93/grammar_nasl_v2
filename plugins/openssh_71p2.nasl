#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90924);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/05/12 14:46:29 $");

  script_cve_id("CVE-2016-1907");
  script_bugtraq_id(81293);
  script_osvdb_id(132882);

  script_name(english:"OpenSSH 6.8p1 - 7.x < 7.1p2 ssh_packet_read_poll2() Packet Handling DoS");
  script_summary(english:"Checks the OpenSSH banner version.");

  script_set_attribute(attribute:"synopsis", value:
"The SSH server running on the remote host is affected by a denial of
service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of OpenSSH running on the remote
host is 6.x equal to or greater than 6.8p1 or 7.x prior to 7.1p2. It
is, therefore, affected by a denial of service vulnerability due to an
out-of-bounds read error that occurs when handling packets. A remote
attacker can exploit this to crash the service or disclose memory
contents.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.openssh.com/txt/release-7.1p2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH version 7.1p2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/05");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/ssh");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "OpenSSH";

# Ensure the port is open.
port = get_service(svc:"ssh", exit_on_fail:TRUE);

# Get banner for service.
banner = tolower(get_kb_item_or_exit("SSH/banner/"+port));

# Ensure target is openssh
if ("openssh" >!< banner) audit(AUDIT_NOT_LISTEN, app_name, port);

# Paranoid scans only
if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Get the version in the backported banner.
v_match = eregmatch(string:banner, pattern:"openssh[-_]([0-9][-._0-9a-z]+)");
if (isnull(v_match)) audit(AUDIT_SERVICE_VER_FAIL, app_name, port);
version = v_match[1];

# Granularity check
if (version =~ "^[67]$") audit(AUDIT_VER_NOT_GRANULAR, app_name, port, version);

# Vuln branches check
if (version !~ "^[67]($|[^0-9])")
  audit(AUDIT_NOT_LISTEN, app_name + " 6.x through 7.x", port);

if (
  # 6.8 >= 6.8p1
  version =~ "^6\.8p([^0]|[0-9][0-9]+)($|[^0-9])" ||
  # 6.x >= 6.9
  version =~ "^6\.(9|[0-9][0-9]+)($|[^0-9])" ||
  # 7.0 (any)
  version =~ "^7\.0($|[^0-9])" ||
  # 7.1
  version == "7.1" ||
  # 7.1p1
  version =~ "^7\.1p[01]($|[^0-9])"
)
{
  security_report_v4(
    port     : port,
    severity : SECURITY_WARNING,
    extra    :
      '\n  Version source    : ' + banner +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 7.1p2\n'
  );
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);
