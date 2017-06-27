#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78655);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/05/12 14:46:30 $");

  script_cve_id("CVE-2014-2653");
  script_bugtraq_id(66459);
  script_osvdb_id(105011);

  script_name(english:"OpenSSH SSHFP Record Verification Weakness");
  script_summary(english:"Checks the version reported in the SSH banner.");

  script_set_attribute(attribute:"synopsis", value:
"A secure shell client on the remote host could be used to bypass host
verification methods.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of OpenSSH running on the remote
host is 6.1 through 6.6.

It is, therefore, affected by a host verification bypass vulnerability
related to SSHFP and certificates that could allow a malicious SSH
server to cause the supplied client to inappropriately trust the
server.");
  # Vendor patch and note
  script_set_attribute(attribute:"see_also", value:"http://thread.gmane.org/gmane.network.openssh.devel/20679");
  # SSHFP RFC "Using DNS to Securely Publish Secure Shell (SSH) Key Fingerprints"
  script_set_attribute(attribute:"see_also", value:"http://tools.ietf.org/html/rfc4255");
  # CVE assignment
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2014/q1/663");
  script_set_attribute(attribute:"solution", value:"Update to version 6.7 or later or apply the vendor patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/23");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh");
  script_require_keys("Settings/ParanoidReport");

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

# Check the version in the backported banner.
match = eregmatch(string:bp_banner, pattern:"openssh[-_]([0-9][-._0-9a-z]+)");
if (empty_or_null(match)) audit(AUDIT_SERVICE_VER_FAIL, "OpenSSH", port);
version = match[1];

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Affected : 6.1 through 6.6
if (version =~ "^6\.[1-6]($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + banner +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 6.7' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "OpenSSH", port, version);
