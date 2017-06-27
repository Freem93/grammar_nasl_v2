#
# (C) Tenable Network Security, Inc.
# 


include("compat.inc");

if (description)
{
 script_id(11932);
 script_version("$Revision: 1.18 $");
 script_cvs_date("$Date: 2011/04/20 01:41:22 $");

 script_cve_id("CVE-2003-0914");
 script_bugtraq_id(9114);
 script_osvdb_id(2866);
 script_xref(name:"Secunia", value:"10300");
 script_xref(name:"SuSE", value:"SUSE-SA:2003:047");
 
 script_name(english:"ISC BIND < 8.3.7 / 8.4.3 Negative Record Cache Poisoning");
 script_summary(english:"Checks the remote BIND version");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to disable the remote name server remotely." );
 script_set_attribute(attribute:"description", value:
"The remote BIND server, according to its version number, is vulnerable to 
a negative cache poison bug that may allow an attacker to disable this
service remotely." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to BIND 8.3.7 or 8.4.3" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/11/27");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/11/26");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
 script_family(english: "DNS");
 script_dependencie("bind_version.nasl");
 script_require_keys("bind/version");
 exit(0);
}

vers = get_kb_item("bind/version");
if(!vers)exit(0);
if(ereg(string:vers, pattern:"^8\.([0-2]\.|3\.[0-6]([^0-9]|$)|4\.[0-2]([^0-9]|$))"))security_hole(53);
