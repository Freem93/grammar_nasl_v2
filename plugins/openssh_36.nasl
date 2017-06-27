#
# (C) Tenable Network Security, Inc.
#

# Thanks to H D Moore for his notification.

include("compat.inc");


if (description)
{
 script_id(11837);
 script_version ("$Revision: 1.40 $");
 script_cvs_date("$Date: 2014/05/02 03:09:37 $");

 script_cve_id("CVE-2003-0682", "CVE-2003-0693", "CVE-2003-0695", "CVE-2004-2760");
 script_bugtraq_id(8628);
 script_osvdb_id(2557, 3456, 6601, 49386);
 script_xref(name:"RHSA", value:"2003:279");
 script_xref(name:"SuSE", value:"SUSE-SA:2003:039");

 script_name(english:"OpenSSH < 3.7.1 Multiple Vulnerabilities");
 script_summary(english:"Checks for the remote SSH version");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote SSH service is affected by various memory bugs." );
 script_set_attribute(attribute:"description",  value:
"According to its banner, the remote SSH server is running a version of
OpenSSH older than 3.7.1.  Such versions are vulnerable to a flaw in
the buffer management functions that might allow an attacker to
execute arbitrary commands on this host.

An exploit for this issue is rumored to exist.

Note that several distributions patched this hole without changing the
version number of OpenSSH.  Since Nessus solely relied on the banner
of the remote SSH server to perform this check, this might be a false
positive. 

If you are running a RedHat host, make sure that the command :

  rpm -q openssh-server

returns :

  openssh-server-3.1p1-13 (RedHat 7.x)
  openssh-server-3.4p1-7  (RedHat 8.0)
  openssh-server-3.5p1-11 (RedHat 9)" );
 script_set_attribute(
   attribute:"see_also", 
   value:"http://marc.info/?l=openbsd-misc&m=106375452423794&w=2"
 );
 script_set_attribute(
   attribute:"see_also", 
   value:"http://marc.info/?l=openbsd-misc&m=106375456923804&w=2"
 );
 script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH 3.7.1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(16);
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/09/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/09/16");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2014 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 if ( ! defined_func("bn_random") )
	script_dependencie("ssh_detect.nasl");
 else
 	script_dependencie("ssh_detect.nasl", "ssh_get_info.nasl", "redhat-RHSA-2003-280.nasl", "redhat_fixes.nasl");
 script_require_ports("Services/ssh", 22);
 exit(0);
}

include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");

if (get_kb_item("CVE-2003-0682")) exit(0);

# Ensure the port is open.
port = get_service(svc:"ssh", exit_on_fail:TRUE);

# Get banner for service.
banner = get_kb_item_or_exit("SSH/banner/"+port);

bp_banner = tolower(get_backport_banner(banner:banner));
if ("openssh" >!< bp_banner) exit(0, "The SSH service on port "+port+" is not OpenSSH.");
if (backported) exit(1, "The banner from the OpenSSH server on port "+port+" indicates patches may have been backported.");

if (ereg(pattern:"openssh[-_](([12]\..*)|(3\.[0-6].*)|(3\.7[^\.]*$))[^0-9]*", string:bp_banner))
  security_hole(port);
