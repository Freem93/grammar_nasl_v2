#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if(description) {
  script_id(11816);
  script_version("$Revision: 1.19 $");

  script_cve_id(
    "CVE-2003-0735", 
    "CVE-2003-0736",  
    "CVE-2003-0737", 
    "CVE-2003-0738"
 );
  script_osvdb_id(
    2410, 
    3842, 
    3843, 
    3844, 
    3845, 
    3846, 
    3847
 );

  script_name(english:"phpWebSite < 0.9.x Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains several PHP scripts that are prone to 
multiple flaws." );
 script_set_attribute(attribute:"description", value:
"There are multiple flaws in the remote version of phpWebSite that may
allow an attacker to gain the control of the remote database, or to
disable this site entirely." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2003/Aug/404" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of this software." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cwe_id(134);

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/08/11");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/08/10");
 script_cvs_date("$Date: 2016/11/02 14:37:08 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:phpwebsite:phpwebsite");
script_end_attributes();

 
 script_summary(english:"SQL Injection and more.");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("phpwebsite_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 script_require_keys("www/phpwebsite");
 exit(0);
}

# Check starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);


# Check each installed instance, stopping if we find a vulnerability.
install = get_kb_item(string("www/", port, "/phpwebsite"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  r = http_send_recv3(method:"GET", item:dir + "/index.php?module=calendar&calendar[view]=day&year=2003%00-1&month=", port:port);
  if(isnull(r))exit(0);
  buf = r[2];

  if(egrep(pattern:".*select.*mod_calendar_events.*", string:buf)) {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
