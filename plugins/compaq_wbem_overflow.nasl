#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(17997);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-2005-4823");
 script_bugtraq_id(12566);
 script_osvdb_id(13843);

 script_name(english:"Compaq WBEM HTTP Server Remote Overflow");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a Compaq Web Management server. 

The remote version of this software is vulnerable to an unspecified
buffer overflow that may allow an attacker to execute arbitrary code
on the remote host with the privileges of the web server process." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/8087" );
 # http://web.archive.org/web/20090416172719/http://www.doecirc.energy.gov/bulletins/p-141.shtml
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4840e0e7" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to HP HTTP Server version 5.96 or later or to the System
Management Homepage Version 2.0 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/04/07");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/02/15");
 script_set_attribute(attribute:"patch_publication_date", value: "2005/05/10");
 script_cvs_date("$Date: 2016/05/04 18:02:13 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


 script_summary(english:"Compaq WBEM Server Version Check");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 2301);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
 
port = get_http_port(default:2301, embedded: 1);

banner = get_http_banner(port:port);
if ( ! banner || "Server: CompaqHTTPServer/" >!< banner ) exit(0);

if ( egrep(pattern:"Server: CompaqHTTPServer/(4\.|5\.([0-9]|[0-8][0-9]|9[0-5])($|[^0-9.]))", string:banner) )
  security_hole(port);
