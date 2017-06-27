#
# This script was written by Felix Huber <huberfelix@webtopia.de>
#
# v. 1.00 (last update 23.11.01)

# Changes by Tenable:
# - re-wrote the code to do pattern matching (RD)
# - updated plugin title, added OSVDB refs (4/1/2009)
# - Updated to use compat.inc, added CVSS score (11/20/2009)


include("compat.inc");

if(description)
{
 script_id(10803);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-2001-0868");
 script_bugtraq_id(3577);
 script_osvdb_id(670, 17086);

 script_name(english:"Redhat Stronghold status / info Request Information Disclosure");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by an
information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"Redhat Stronghold Secure Server File System Disclosure Vulnerability

The problem:
In Redhat Stronghold from versions 2.3 up to 3.0 a flaw exists that
allows a remote attacker to disclose sensitive system files including
the httpd.conf file, if a restricted access to the server status
report is not enabled when using those features.
This may assist an attacker in performing further attacks.

By trying the following urls, an attacker can gather sensitive
information:
http://target/stronghold-info will give information on configuration
http://target/stronghold-status will return among other information
the list of request made

Please note that this attack can be performed after a default
installation. The vulnerability seems to affect all previous version
of Stronghold." );
 script_set_attribute(attribute:"solution", value:
"Patch was released (November 19, 2001)" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2001/11/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/11/23");
 script_cvs_date("$Date: 2011/03/17 01:57:40 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


 script_summary(english:"Redhat Stronghold File System Disclosure");

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2001-2011 Felix Huber");
 script_family(english:"CGI abuses");
 script_dependencie( "http_version.nasl");
 script_require_keys("www/apache");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
 req = http_get(item:"/stronghold-info", port:port);
 r   = http_keepalive_send_recv(port:port, data:req);
 if (! r ) exit(0);
 if("Stronghold Server Information" >< r)
 {
   security_warning(port);
   exit(0);
 }

  req = http_get(item:"/stronghold-status", port:port);
  r   = http_keepalive_send_recv(port:port, data:req);
  if("Stronghold Server Status for" >< r)security_warning(port);
}
