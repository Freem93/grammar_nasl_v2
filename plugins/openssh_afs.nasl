#
# This script was written by Thomas Reinke <reinke@securityspace.com>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, formatted output, enhanced solution, changed plugin family (8/18/09)


include("compat.inc");

if(description)
{
 script_id(10954);
 script_version ("$Revision: 1.27 $");
 script_cvs_date("$Date: 2012/02/21 19:28:56 $");

 script_cve_id("CVE-2002-0575");
 script_bugtraq_id(4560);
 script_osvdb_id(781);
 
 script_name(english:"OpenSSH Kerberos TGT/AFS Token Passing Remote Overflow");
 script_summary(english:"Checks for the remote SSH version");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote host." );
 script_set_attribute(attribute:"description", value:
"You are running a version of OpenSSH older than OpenSSH 3.2.1.

A buffer overflow exists in the daemon if AFS is enabled on
your system, or if the options KerberosTgtPassing or
AFSTokenPassing are enabled.  Even in this scenario, the
vulnerability may be avoided by enabling UsePrivilegeSeparation.

Versions prior to 2.9.9 are vulnerable to a remote root
exploit. Versions prior to 3.2.1 are vulnerable to a local
root exploit." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 3.2.1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/05/12");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/05/22");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2012 Thomas Reinke");
 script_family(english:"Gain a shell remotely");
 if (  ! defined_func("bn_random") ) 
	script_dependencie("ssh_detect.nasl");
 else
	script_dependencie("ssh_detect.nasl", "redhat-RHSA-2002-131.nasl");
 script_require_ports("Services/ssh", 22);
 exit(0);
}

include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");

if (get_kb_item("CVE-2002-0640")) exit(0);

# Ensure the port is open.
port = get_service(svc:"ssh", exit_on_fail:TRUE);

# Get banner for service.
banner = get_kb_item_or_exit("SSH/banner/"+port);

bp_banner = tolower(get_backport_banner(banner:banner));
if ("openssh" >!< bp_banner) exit(0, "The SSH service on port "+port+" is not OpenSSH.");
if (backported) exit(1, "The banner from the OpenSSH server on port "+port+" indicates patches may have been backported.");

if (ereg(pattern:"openssh[-_](2\..*|3\.([01].*|2\.0))", string:bp_banner))
  security_hole(port);
