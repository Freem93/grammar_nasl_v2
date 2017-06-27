#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90022);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/04/28 18:52:12 $");

  script_osvdb_id(135128);

  script_name(english:"OpenSSH < 7.2 Untrusted X11 Forwarding Fallback Security Bypass");
  script_summary(english:"Checks the OpenSSH banner version.");

  script_set_attribute(attribute:"synopsis", value:
"The SSH server running on the remote host is affected by a security
bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of OpenSSH running on the remote
host is prior to 7.2. It is, therefore, affected by a security bypass
vulnerability due to a flaw in ssh(1) that is triggered when it falls
back from untrusted X11 forwarding to trusted forwarding when the
SECURITY extension is disabled by the X server. This can result in
untrusted X11 connections that can be exploited by a remote attacker.");
  script_set_attribute(attribute:"see_also", value:"http://www.openssh.com/txt/release-7.2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH version 7.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/18");

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
include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");

# Ensure the port is open.
port = get_service(svc:"ssh", exit_on_fail:TRUE);

# Get banner for service.
banner = get_kb_item_or_exit("SSH/banner/" + port);

bp_banner = tolower(get_backport_banner(banner:banner));
if ("openssh" >!< bp_banner)
  audit(AUDIT_NOT_LISTEN, "OpenSSH", port);
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);
if (backported)
  audit(code:0, AUDIT_BACKPORT_SERVICE, port, "OpenSSH");

# Check the version in the backported banner.
match = eregmatch(string:bp_banner, pattern:"openssh[-_]([0-9][-._0-9a-z]+)");
if (isnull(match))
  audit(AUDIT_SERVICE_VER_FAIL, "OpenSSH", port);
version = match[1];

fix = "7.2";
if (
  version =~ "^[0-6]\." ||
  version =~ "^7\.[0-1]($|[^0-9])"
   )
{
  items = make_array("Version source", banner,
                     "Installed version", version,
                     "Fixed version", fix);
  order = make_list("Version source", "Installed version", "Fixed version");
  report = report_items_str(report_items:items, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
  exit(0);

}
else audit(AUDIT_LISTEN_NOT_VULN, "OpenSSH", port, version);
