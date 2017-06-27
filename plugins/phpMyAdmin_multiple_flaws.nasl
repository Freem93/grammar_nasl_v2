#
# (C) Tenable Network Security, Inc.
#

# Ref: 
#  Date: 18 Jun 2003 16:33:36 -0000
#  Message-ID: <20030618163336.11333.qmail@www.securityfocus.com>
#  From: Lorenzo Manuel Hernandez Garcia-Hierro <security@lorenzohgh.com>
#  To: bugtraq@securityfocus.com  
#  Subject: phpMyAdmin XSS Vulnerabilities, Transversal Directory Attack ,
#   Information Encoding Weakness and Path Disclosures
#


include("compat.inc");

if (description)
{
 script_id(11761);
 script_version ("$Revision: 1.26 $");
 script_cvs_date("$Date: 2011/12/15 22:43:55 $");

 script_bugtraq_id(7962, 7963, 7964, 7965);
 script_osvdb_id(
   8450,
   8451,
   8452,
   8453,
   8454,
   8455,
   8456,
   8457,
   8458,
   8459,
   8460,
   8461,
   8462,
   8463,
   8464,
   8465,
   8466,
   8467,
   8468,
   8469,
   8470,
   8471,
   8472,
   8473,
   8474,
   8475,
   8476,
   8477,
   8478,
   8479,
   8480,
   8481,
   8482,
   8483,
   8484,
   8485,
   8486,
   8487,
   8488,
   8489,
   8490,
   8491,
   8492,
   8493,
   8494,
   8495,
   8496,
   8497,
   8498,
   8499,
   8500,
   8501,
   8502,
   8503,
   8504,
   8505
 );

 script_name(english:"phpMyAdmin < 2.5.2 Multiple Vulnerabilities");
 script_summary(english:"Checks for the presence of phpMyAdmin");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that suffers from
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of phpMyAdmin that is vulnerable
to several attacks :

 - It may be tricked into disclosing the physical path of the remote PHP
   installation.
   
 - It is vulnerable to cross-site scripting that could allow an attacker
   to steal the cookies of your users.
   
 - It is vulnerable to a flaw that could allow an attacker to list the
   contents of arbitrary directories on the remote server.

An attacker could use these flaws to gain more knowledge about the remote
host and therefore set up more complex attacks against it." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/325641" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/327511" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyAdmin 2.5.2 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/06/18");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/06/18");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("phpMyAdmin_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 script_require_keys("www/phpMyAdmin", "www/PHP");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, php:TRUE);


# Test an install.
install = get_kb_item(string("www/", port, "/phpMyAdmin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];
  test_cgi_xss(port: port, dirs: make_list(dir), cgi: "/db_details_importdocsql.php",
 pass_str: "Ignoring file passwd",
 qs: "submit_show=true&do=import&docpath=../../../../../../../../../../etc");
}
