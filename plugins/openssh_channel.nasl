#
# This script was written by Thomas reinke <reinke@e-softinc.com>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, formatted output, changed family (8/18/09)


include("compat.inc");

if (description)
{
  script_id(10883);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2011/11/15 15:40:21 $");

  script_cve_id("CVE-2002-0083");
  script_bugtraq_id(4241);
  script_osvdb_id(730);

  script_name(english:"OpenSSH < 3.1 Channel Code Off by One Remote Privilege Escalation");
  script_summary(english:"Checks for the remote OpenSSH version");
 
  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote host." );
  script_set_attribute(attribute:"description", value:
"You are running a version of OpenSSH which is older than 3.1.

Versions prior than 3.1 are vulnerable to an off by one error
that allows local users to gain root access, and it may be
possible for remote users to similarly compromise the daemon
for remote access.

In addition, a vulnerable SSH client may be compromised by
connecting to a malicious SSH daemon that exploits this
vulnerability in the client code, thus compromising the
client system." );
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH 3.1 or apply the patch for
prior versions. (See: http://www.openssh.org)" );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(189);
	
  script_set_attribute(attribute:"plugin_publication_date", value: "2002/03/07");
  script_set_attribute(attribute:"vuln_publication_date", value: "2002/03/07");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (c) 2002-2011 Thomas Reinke");
  script_family(english:"Gain a shell remotely");
  script_dependencie("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
 
  exit(0);
}

include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");

# Ensure the port is open.
port = get_service(svc:"ssh", exit_on_fail:TRUE);

# Get banner for service.
banner = get_kb_item_or_exit("SSH/banner/"+port);

bp_banner = tolower(get_backport_banner(banner:banner));
if ("openssh" >!< bp_banner) exit(0, "The SSH service on port "+port+" is not OpenSSH.");
if (backported) exit(1, "The banner from the OpenSSH server on port "+port+" indicates patches may have been backported.");

if (ereg(pattern:"openssh[-_](2\..*|3\.0)" , string:bp_banner))
  security_hole(port);
