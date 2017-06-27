#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(18101);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2005-1225", "CVE-2005-1226");
  script_bugtraq_id(13287, 13289);
  script_osvdb_id(15881, 50907, 50908);

  script_name(english:"Coppermine Photo Gallery < 1.3.2 Multiple SQL Injections");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple issues." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the version of Coppermine Photo
Gallery installed on the remote host suffers from multiple SQL
injection vulnerabilities due to its failure to sanitize user-supplied
cookie data before using it in SQL queries in the scripts
'include/functions.inc.php' as well as 'zipdownload.php'.  An attacker
may be able to use the first flaw to reveal sensitive data and the
second to download any file accessible to the web server userid on the
remote host, although access to 'zipdownload.php' is not enabled by
default. 

In addition, the application reportedly stores passwords in its
database as plaintext.  A attacker who successfully exploits one of
the SQL injection flaws above is likely to easily gain control of the
affected application." );
 script_set_attribute(attribute:"see_also", value:"http://www.waraxe.us/advisory-42.html" );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=111402186304179&w=2" );
 script_set_attribute(attribute:"see_also", value:"http://coppermine-gallery.net/forum/index.php?topic=17134" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Coppermine Photo Gallery version 1.3.3 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/04/21");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/04/20");
 script_cvs_date("$Date: 2016/11/17 21:38:53 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:coppermine:coppermine_photo_gallery");
script_end_attributes();

 
  summary["english"] = "Checks for version of Coppermine Photo Gallery";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("coppermine_gallery_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/coppermine_photo_gallery"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  # nb: catches versions like "1.3.0-Nuke" too.
  if (ver =~ "(0|1\.([0-2]|3\.[0-2]([^0-9]|$)))")
  {
   security_hole(port);
   set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  }
}
