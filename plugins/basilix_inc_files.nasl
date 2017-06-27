#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10601);
 script_bugtraq_id(2198);
 script_osvdb_id(497);
 script_cve_id("CVE-2001-1044");
 script_version ("$Revision: 1.25 $");
 
 script_name(english:"Basilix Webmail .class / .inc Direct Request Remote Information Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to an
information disclosure attack." );
 script_set_attribute(attribute:"description", value:
"It is possible to download the include files on the remote BasiliX
webmail service.  An attacker may use these to obtain the MySQL
authentication credentials." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityoffice.net/articles/basilix/index.php" );
 script_set_attribute(attribute:"solution", value:
"Put a handler in your web server for the .inc and .class files." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");


 script_set_attribute(attribute:"plugin_publication_date", value: "2001/01/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/01/12");
 script_cvs_date("$Date: 2011/03/14 21:48:01 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "Checks for the presence of include files";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001-2011 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/basilix");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/basilix"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  foreach file (make_list("/inc/sendmail.inc", "class/mysql.class")) {
    w = http_send_recv3(method:"GET", item:string(dir, file), port:port);
    if (isnull(w)) exit(0);
    r = w[2];

    if("BasiliX" >< r)
     {
      if("This program is free software" >< r) 
       {
        security_warning(port);
        exit(0);
       }
     }
  }
}
