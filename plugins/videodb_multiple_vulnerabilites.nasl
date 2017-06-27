#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(16140);
 script_version ("$Revision: 1.16 $");
 script_bugtraq_id(12219,12224);
 script_osvdb_id(12796, 53438, 53439);

 script_name(english:"VideoDB < 2.0.2 Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server has a PHP script that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is VideoDB, a web-based video dabatase manager 
written in PHP.

The remote version of this software is vulnerable to a SQL injection
attack due to a lack of filtering on user-supplied input.  An attacker
may exploit this flaw to modify the remote database. 

This software may be vulnerable to an unauthorized access attack in
the file 'edit.php' that may allow an attacker to edit database
entries, as well as an unspecified cross-site scripting issue." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to VideoDB 2.0.2 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/01/12");
 script_set_attribute(attribute:"patch_publication_date", value: "2005/01/05");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/01/05");
 script_cvs_date("$Date: 2016/11/29 20:13:36 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:videodb:videodb");
 script_end_attributes();
 
 script_summary(english:"Checks for the version of VideoDB");
 
 script_category(ACT_ATTACK);
  
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port))
 exit(1,"The remote web server on port "+port+" does not support PHP.");

foreach dir (cgi_dirs())
{
  res = http_send_recv3(method:"GET", item:"/index.php", port:port);
  if (isnull(res)) exit(1,"Null response to index.php request.");
  if ( egrep(pattern:"^span class=.*a href=.*www\.splitbrain\.org/go/videodb.*v\.(1_|2_0_0)", string:res[2]))
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
   }
}
