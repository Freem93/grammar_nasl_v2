#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(17704);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/12 14:46:30 $");

  script_cve_id("CVE-2007-2243");
  script_bugtraq_id(23601);
  script_osvdb_id(34600);

  script_name(english:"OpenSSH S/KEY Authentication Account Enumeration");
  script_summary(english:"Checks if OpenSSH is installed.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"When OpenSSH has S/KEY authentication enabled, it is possible to
remotely determine if an account configured for S/KEY authentication
exists. 

Note that Nessus has not attempted to exploit the issue but has
instead only checked if OpenSSH is running on the remote host. As a
result, it will not detect if the remote host has implemented a
workaround.");
# https://web.archive.org/web/20110723143430/http://www.helith.net/txt/openssh_system_account_enumeration_if_s-key_is_used.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?907640b9");
  script_set_attribute(attribute:"solution", value:
"A patch currently does not exist for this issue. As a workaround,
either set 'ChallengeResponseAuthentication' in the OpenSSH config to
'no' or use a version of OpenSSH without S/KEY support compiled in.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(287);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_require_keys("Settings/PCI_DSS");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

if (!get_kb_item("Settings/PCI_DSS")) exit(0, "PCI-DSS compliance checking is not enabled.");

# Ensure the port is open.
port = get_service(svc:'ssh', exit_on_fail:TRUE);

# Get banner for service
banner = get_kb_item_or_exit("SSH/banner/"+port);

if ("openssh" >!< tolower(banner)) exit(0, "The SSH service on port "+port+" is not OpenSSH.");

match = eregmatch(string:tolower(banner), pattern:"openssh[-_]([0-9][-._0-9a-z]+)");
if (isnull(match)) exit(1, "Could not parse the version string in the banner from port "+port+".");
version = match[1];

if (report_verbosity > 0)
{
  report =
    '\n  Version source    : ' + banner +
    '\n  Installed version : ' + version +
    '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);
