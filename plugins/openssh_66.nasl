#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73079);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/06/15 18:43:50 $");

  script_cve_id("CVE-2014-1692", "CVE-2014-2532");
  script_bugtraq_id(65230, 66355);
  script_osvdb_id(102611, 104578);

  script_name(english:"OpenSSH < 6.6 Multiple Vulnerabilities");
  script_summary(english:"Checks OpenSSH banner version.");

  script_set_attribute(attribute:"synopsis", value:
"The SSH server on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of OpenSSH running on the remote
host is prior to 6.6. It is, therefore, affected by the following
vulnerabilities :

  - A flaw exists due to a failure to initialize certain
    data structures when makefile.inc is modified to enable
    the J-PAKE protocol. An unauthenticated, remote attacker
    can exploit this to corrupt memory, resulting in a
    denial of service condition and potentially the
    execution of arbitrary code. (CVE-2014-1692)

  - An error exists related to the 'AcceptEnv' configuration
    setting in sshd_config due to improper processing of
    wildcard characters. An unauthenticated, remote attacker
    can exploit this, via a specially crafted request, to
    bypass intended environment restrictions.
    (CVE-2014-2532)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.openssh.com/txt/release-6.6");
  script_set_attribute(attribute:"see_also", value:"http://www.gossamer-threads.com/lists/openssh/dev/57663#57663");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSH version 6.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/18");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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

# Affected : < 6.6
if (
  version =~ "^[0-5]\." ||
  version =~ "^6\.[0-5]($|[^0-9])"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + banner +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 6.6\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "OpenSSH", port, version);
