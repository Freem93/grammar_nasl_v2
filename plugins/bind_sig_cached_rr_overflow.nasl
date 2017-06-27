#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11152);
 script_version("$Revision: 1.27 $");
 script_cvs_date("$Date: 2012/06/14 20:15:05 $");

 script_cve_id("CVE-2002-1219");
 script_bugtraq_id(6160);
 script_osvdb_id(869);
 script_xref(name:"Secunia", value:"7494");
 script_xref(name:"SuSE", value:"SUSE-SA:2002:044");
 
 script_name(english:"ISC BIND named SIG Resource Server Response RR Overflow");
 script_summary(english:"Checks the remote BIND version");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to use the remote name server to execute arbitrary code on
the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote BIND server, according to its version number, is affected
by the 'SIG cached RR overflow' vulnerability. 

An attacker may use this flaw to gain a shell on this system.");
 script_set_attribute(attribute:"solution", value:
"Upgrade to BIND 8.2.7, 8.3.4 or 4.9.11.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value:"2002/11/12");
 script_set_attribute(attribute:"vuln_publication_date", value:"2002/11/12");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2012 Tenable Network Security, Inc.");
 script_family(english: "DNS");

 script_dependencie("bind_version.nasl");
 script_require_keys("bind/version");
 exit(0);
}





vers = get_kb_item("bind/version");
if(!vers)exit(0);
if(ereg(string:vers,
	 pattern:"^8\.2\.[0-6][^0-9]*$"))security_hole(53);
	 
if(ereg(string:vers,
	 pattern:"^8\.3\.[0-3][^0-9]*$"))security_hole(53);
	 
if(ereg(string:vers,
	 pattern:"^4\.9\.([0-9][^0-9]*$|10)"))security_hole(53);	 	 
