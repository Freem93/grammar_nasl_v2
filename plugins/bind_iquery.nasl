#
# (C) Tenable Network Security, Inc.
#

# This script replaces bind_bof.nes


include("compat.inc");

if (description)
{
 script_id(10329);
 script_version("$Revision: 1.18 $");
 script_cvs_date("$Date: 2011/12/09 22:22:17 $");

 script_cve_id("CVE-1999-0009");
 script_bugtraq_id(134);
 script_osvdb_id(913);
 
 script_name(english:"ISC BIND < 4.9.7 / 8.1.2 Inverse-Query Remote Overflow");
 script_summary(english:"Checks the remote BIND version");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to use the remote name server to break into the
remote host." );
 script_set_attribute(attribute:"description", value:
"The remote BIND server, according to its version number, is 
vulnerable to an inverse query overflow which could allow an attacker 
to execute arbitrary code on the remote host." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to BIND 8.1.2 or 4.9.7 or newer" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/04/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "1998/04/08");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2011 Tenable Network Security, Inc.");
 script_family(english: "DNS");
 script_dependencie("bind_version.nasl");
 script_require_keys("bind/version");
 exit(0);
}

vers = get_kb_item("bind/version");
if(!vers)exit(0);
if(ereg(string:vers,
	 pattern:"^8\.((0\..*)|(1\.[0-1]([^0-9]|$))).*"))security_hole(53);

if(ereg(string:vers,
    	pattern:"^4\.([0-8]\.|9\.[0-6]([^0-9]|$)).*"))security_hole(53);

