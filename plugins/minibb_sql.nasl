#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
 script_id(15763);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-2004-2456");
 script_bugtraq_id(11688);
 script_osvdb_id(11711);

 script_name(english:"miniBB index.php user Parameter SQL Injection");
 script_summary(english:"Determine if MiniBB can be used to execute arbitrary SQL commands");

 script_set_attribute( attribute:"synopsis",  value:
"A web application on the remote host has a SQL injection vulnerability." );
 script_set_attribute( attribute:"description",  value:
"The remote host is using the miniBB forum management system.

According to its version number, this forum is vulnerable to a
SQL injection attack.  Input to the 'user' parameter of index.php
not properly sanitized.  A remote attacker could exploit this to
execute arbitrary SQL queries against the remote database." );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to miniBB 1.7f or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/19");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/10/28");
 script_cvs_date("$Date: 2011/03/17 01:57:39 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");

 script_dependencie("minibb_xss.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
kb   = get_kb_item("www/" + port + "/minibb");
if ( ! kb ) exit(0);
matches = eregmatch(string:kb, pattern:"^(.+) under (.*)$");
if ( ereg(pattern:"^(0\.|1\.[0-6][^0-9]|7([a-e]|$))", string:matches[1]) )
{
     security_hole(port);
     set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
}
