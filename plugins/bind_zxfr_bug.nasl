#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(10549);
 script_version("$Revision: 1.21 $");
 script_cvs_date("$Date: 2011/08/08 17:20:26 $");

 script_cve_id("CVE-2000-0887");
 script_bugtraq_id(1923);
 script_osvdb_id(448);
 
 script_name(english:"ISC BIND < 8.2.2-P7 Compressed ZXFR Name Service Query DoS");
 script_summary(english:"Checks the remote BIND version");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to disable the remote name server remotely." );
 script_set_attribute(attribute:"description", value:
"The remote BIND server, according to its version number, is vulnerable 
to the 'ZXFR bug' that could allow an attacker to crash this service
remotely." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to BIND 8.2.2-P7" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2000/11/12");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/11/07");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2011 Tenable Network Security, Inc.");
 script_family(english: "DNS");
 script_dependencie("bind_version.nasl");
 script_require_keys("bind/version");
 exit(0);
}





vers = get_kb_item("bind/version");
if(!vers)exit(0);
if(ereg(string:vers,
	 pattern:"^8\.2\.2(\-P[1-6])*$"))security_hole(53);
