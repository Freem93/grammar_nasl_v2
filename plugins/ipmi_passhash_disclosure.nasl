#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80101);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/23 20:31:32 $");

  script_cve_id("CVE-2013-4786");
  script_bugtraq_id(61076);
  script_osvdb_id(95057);

  script_name(english:"IPMI v2.0 Password Hash Disclosure");
  script_summary(english:"Checks if the server supports IPMI v2.0.");

  script_set_attribute(attribute:"synopsis", value:"The remote host supports IPMI version 2.0.");
  script_set_attribute(attribute:"description", value:
"The remote host supports IPMI v2.0. The Intelligent Platform
Management Interface (IPMI) protocol is affected by an information
disclosure vulnerability due to the support of RMCP+ Authenticated
Key-Exchange Protocol (RAKP) authentication. A remote attacker can
obtain password hash information for valid user accounts via the HMAC
from a RAKP message 2 response from a BMC.");
  script_set_attribute(attribute:"solution", value:
"There is no patch for this vulnerability; it is an inherent problem
with the specification for IPMI v2.0. Suggested mitigations include :

  - Disabling IPMI over LAN if it is not needed.

  - Using strong passwords to limit the successfulness of
    off-line dictionary attacks.

  - Using Access Control Lists (ACLs) or isolated networks
    to limit access to your IPMI management interfaces.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"see_also", value:"http://fish2.com/ipmi/remote-pw-cracking.html");
script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("ipmi_supported_versions.nbin");
  script_require_ports("Services/udp/asf-rmcp");

  exit(0);
}

include('audit.inc');
include("global_settings.inc");
include('misc_func.inc');

local_var ipmi_channels, ipmi_v2_enabled;

port = get_service(svc:"asf-rmcp", ipproto:"udp", exit_on_fail:TRUE);

ipmi_channels = get_kb_list("ipmi/"+port+"/channels/*/v2.0");

if (isnull(ipmi_channels ))
{
  audit(AUDIT_NOT_DETECT, "IPMI", port);
}

ipmi_v2_enabled = FALSE;
foreach ipmi_channel_v2_enabled (ipmi_channels)
{
  if (ipmi_channel_v2_enabled == 1)
  {
    ipmi_v2_enabled = TRUE;
    break;
  }
}

if (!ipmi_v2_enabled)
{
  audit(AUDIT_LISTEN_NOT_VULN, "IPMI", port);
}

# Report our findings.
report = '';
if (report_verbosity > 0)
{
  report =
    '\nNessus detected that the remote server has IPMI v2.0 implemented.'+
    '\nRemote unauthenticated users will be able to get password hashes'+
    '\nfor valid users.'+
    '\n';
}

security_hole(port:port, proto:"udp", extra:report);
