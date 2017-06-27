#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11198);
 script_version ("$Revision: 1.17 $");
 script_bugtraq_id(6588, 6589, 6590);
 script_xref(name:"OSVDB", value:"50549");
 script_xref(name:"OSVDB", value:"50550");
 script_xref(name:"Secunia", value:"7854");

 script_name(english:"BitKeeper Daemon Mode diff Shell Command Injection");
 script_summary(english:"Checks for the remote banner");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote revision control server has a remote command
execution vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running version 3.0.x of BitKeeper.
Some versions of this service are known to allow anyone to execute
arbitrary commands with the privileges of the BitKeeper daemon.

*** Nessus did not check for this vulnerability, but solely
*** relied on the banner of the remote server to issue this warning.

BitKeeper is also reportedly vulnerable to a race condition
involving temporary file creation.  Nessus did not check for this issue." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/vulnwatch/2003/q1/19"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of BitKeeper."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/01/16");
 script_cvs_date("$Date: 2016/11/15 13:39:08 $");
 script_set_attribute(attribute:"plugin_type", value: "remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Gain a shell remotely");
 
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8080);
 script_require_keys("www/BitKeeper");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8080);

banner = get_http_banner(port:port, exit_on_fail: 1);
 
 # The original exploit says that the bug can be exploited
 # by doing : http://host:port/diffs/foo.c@%27;echo%20%3Eiwashere%27?nav=index.html|src/|hist/foo.c
 # but since no repository is given, I'm a bit surprised. 
 # At this time, we'll simply yell if we see the banner
 #
 if("Server: bkhttp/0.3" >< banner)security_hole(port);
