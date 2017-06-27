#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(25446);
 script_version("$Revision: 1.15 $");

 script_cve_id("CVE-2007-0563","CVE-2007-0564");
 script_bugtraq_id(22184);
 script_osvdb_id(32959, 32960, 32961);

 script_name(english:"Symantec Web Security (SWS) Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of Symantec Web Security on the
remote host is vulnerable to denial of service and cross-site
scripting attacks." );
 script_set_attribute(attribute:"solution", value:
"Upgrade at least to version 3.0.1.85." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2007/06/07");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/01/24");
 script_set_attribute(attribute:"patch_publication_date", value: "2007/01/24");
 script_cvs_date("$Date: 2016/05/06 17:22:01 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:symantec:web_security");
script_end_attributes();

 
 script_summary(english:"Checks for SWS flaws");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
 
 script_family(english:"CGI abuses");
 script_dependencie("symantec_ws_detection.nasl");
 script_require_ports("Services/www", 8002);
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/www");
if ( ! port ) port = 8002;
if(!get_port_state(port)) exit(0);

version=get_kb_item(string("www/", port, "/SWS"));
if (version) {
	if (ereg(pattern:"^(2\.|3\.0\.(0|1\.([0-9]|[1-7][0-9]|8[0-4])$))", string:version))
	{
		security_warning(port);
		set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	}
}
