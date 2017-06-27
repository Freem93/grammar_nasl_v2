#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10029);
 script_version("$Revision: 1.36 $");
 script_cvs_date("$Date: 2012/12/10 14:56:53 $");

 script_cve_id("CVE-1999-0833", "CVE-1999-0835", "CVE-1999-0837", "CVE-1999-0848", "CVE-1999-0849", "CVE-1999-0851");
 script_bugtraq_id(788);
 script_osvdb_id(24, 9736, 34749, 34750, 34751, 34752);
 script_xref(name:"CERT-CC", value:"CA-1999-14");
 
 script_name(english:"ISC BIND < 4.9.7-REL / 8.2.2-P5 Multiple Remote Vulnerabilities");
 script_summary(english:"Checks the remote BIND version");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to use the remote name server to execute arbitrary code on
the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote BIND server, according to its version number, is vulnerable to 
several attacks that could allow an attacker to execute arbitrary code on 
the remote host.");
 script_set_attribute(attribute:"solution", value:"Upgrade to BIND 8.2.2-P5 / 4.9.7-REL.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"1999/11/10");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/11/11");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2012 Tenable Network Security, Inc.");
 script_family(english:"DNS");
 script_dependencie("bind_version.nasl");
 script_require_keys("bind/version");
 exit(0);
}

vers = string(get_kb_item("bind/version"));
if(!vers)exit(0);

if(vers[0] == "4") 
{ 
 if(ereg(string:vers, pattern:"^4\.([0-8]\..*|9\.[0-6]([^0-9]|$))"))
 {
  security_hole(53);
  exit(0);
 }
}
else
   if(ereg(string:vers, pattern:"^8\.([01]\..*|2\.([01].*|2-P[0-2]))"))
     	security_hole(53);
