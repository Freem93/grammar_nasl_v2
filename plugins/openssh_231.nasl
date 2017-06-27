#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10608);
 script_version ("$Revision: 1.25 $");
 script_cvs_date("$Date: 2012/06/19 21:49:20 $");

 script_cve_id("CVE-2001-1585");
 script_bugtraq_id(2356);
 script_osvdb_id(504);

 script_name(english:"OpenSSH 2.3.1 SSHv2 Public Key Authentication Bypass");
 script_summary(english:"Checks for the remote SSH version");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a
authentication bypass vulnerability." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running OpenSSH 2.3.1.

This version is vulnerable to a flaw that allows any attacker who can
obtain the public key of a valid SSH user to log into this host
without any authentication." );
 script_set_attribute(attribute:"see_also", value:"http://www.openbsd.org/advisories/ssh_bypass.txt" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH 2.3.2." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(287);
	
 script_set_attribute(attribute:"plugin_publication_date", value: "2001/02/09");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/02/08");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2012 Tenable Network Security, Inc.");
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

if (ereg(pattern:"openssh[-_]2\.3\.1([^0-9]|$)", string:bp_banner))
  security_hole(port);
