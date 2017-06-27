#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(11712);
 script_version ("$Revision: 1.21 $");
 script_cvs_date("$Date: 2014/06/06 18:48:43 $");

 script_cve_id("CVE-2003-0386");
 script_bugtraq_id(7831);
 script_osvdb_id(2112);
 script_xref(name:"CERT", value:"978316");

 script_name(english:"OpenSSH < 3.6.2 Reverse DNS Lookup Bypass");
 script_summary(english:"Checks for the remote SSH version");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by DNS
lookup bypass vulnerability." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host appears to be running
OpenSSH-portable version 3.6.1 or older.

There is a flaw in such version that could allow an attacker to
bypass the access controls set by the administrator of this server.

OpenSSH features a mechanism that can restrict the list of
hosts a given user can log from by specifying a pattern
in the user key file (ie: *.mynetwork.com would let a user
connect only from the local network).

However there is a flaw in the way OpenSSH does reverse DNS lookups.
If an attacker configures a DNS server to send a numeric IP address
when a reverse lookup is performed, this mechanism could be
circumvented." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH 3.6.2 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/06/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/06/05");
 script_set_attribute(attribute:"plugin_type", value: "remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2014 Tenable Network Security, Inc.");
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

if (ereg(pattern:"openssh[-_]((1\..*)|(2\..*)|(3\.([0-5][^0-9]|6(\.[01])?$)))", string:bp_banner))
  security_hole(port);
