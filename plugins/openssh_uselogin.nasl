#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(10439);
 script_version ("$Revision: 1.27 $");
 script_cvs_date("$Date: 2011/11/15 15:40:21 $");

 script_cve_id("CVE-2000-0525");
 script_bugtraq_id(1334);
 script_osvdb_id(341);

 script_name(english:"OpenSSH < 2.1.1 UseLogin Local Privilege Escalation");
 script_summary(english:"Checks for the remote OpenSSH version");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a local 
privilege escalation vulnerability." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host appears to be 
running OpenSSH version older than 2.1.1. Such versions are
reportedly affected by a local privilege esclation 
vulnerability.

If the UseLogin option is enabled, then sshd does not switch
to the uid of the user logging in.  Instead, sshd relies on 
login(1) to do the job.  However, if the user specifies a 
command for remote execution, login(1) cannot be used and 
sshd fails to set the correct user id, so the command is run 
with the same privilege as sshd (usually root privileges)." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH 2.1.1 or make sure that the 
option UseLogin is set to no in sshd_config" );
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");

 script_set_attribute(attribute:"plugin_publication_date", value: "2000/06/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/10/06");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2011 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
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

if (ereg(pattern:"openssh[-_]((1\.)|(2\.[0-1]))", string:bp_banner))
  security_hole(port);
