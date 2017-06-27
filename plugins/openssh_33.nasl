#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# also covers CVE-2002-0765


include("compat.inc");

if (description)
{
 script_id(11031);
 script_version ("$Revision: 1.32 $");
 script_cvs_date("$Date: 2012/02/21 20:21:10 $");

 script_cve_id("CVE-2002-0639", "CVE-2002-0640");
 script_bugtraq_id(5093);
 script_osvdb_id(839, 6245);
 
 script_name(english:"OpenSSH < 3.4 Multiple Remote Overflows");
 script_summary(english:"Checks for the remote SSH version");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected multiple
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host appears to be 
running OpenSSH version 3.4 or older. Such versions are 
reportedly affected by multiple flaws. An attacker may 
exploit these vulnerabilities to gain a shell on the remote 
system.

Note that several distributions patched this hole without 
changing the version number of OpenSSH. Since Nessus solely 
relied on the banner of the remote SSH server to perform this 
check, this might be a false positive.

If you are running a RedHat host, make sure that the command :
          rpm -q openssh-server
	  
Returns :
	openssh-server-3.1p1-6" );
 script_set_attribute(attribute:"see_also", value:"http://www.openssh.com/txt/preauth.adv" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH 3.4 or contact your vendor for a patch." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/06/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/06/26");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2012 Tenable Network Security, Inc.");
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

if (ereg(pattern:"openssh[-_]((1\..*)|(2\..*)|(3\.([0-3](\.[0-9]*)*)))", string:bp_banner))
  security_hole(port);
