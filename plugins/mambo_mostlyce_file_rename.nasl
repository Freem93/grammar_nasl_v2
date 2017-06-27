#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(30110);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2008-7215");
  script_bugtraq_id(27472);
  script_osvdb_id(42532);
  script_xref(name:"EDB-ID", value:"4845");

  script_name(english:"Mambo MOStlyCE Mambot Arbitrary File Rename");
  script_summary(english:"Tries to rename a nonexistent file");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
several issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running MOStlyContent Editor (MOStlyCE), the
default WYSIWYG editor for Mambo. 

The version of MOStlyCE installed on the remote host contains a design
flaw that may allow an attacker to rename files subject to the
privileges of the web server user id.  An unauthenticated attacker may
be able to leverage this issue to disable the application and/or
uncover the contents of sensitive files by, say, renaming Mambo's
configuration file and then issuing a request for the file using its
new name. 

There is also a reported cross-site scripting vulnerability involving
the 'Command' parameter of MOStlyCE's 'connector.php' script, although
Nessus has not verified this." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Jan/385" );
 script_set_attribute(attribute:"see_also", value:"http://forum.mambo-foundation.org/showthread.php?t=10158" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Feb/424" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MOStlyCE version 3.0 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/01/28");
 script_cvs_date("$Date: 2016/10/27 15:03:54 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("mambo_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/mambo_mos");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0, "The web server on port "+port+" does not support PHP");


# Test an install.
install = get_kb_item(string("www/", port, "/mambo_mos"));
if (isnull(install)) exit(0, "Mambo is not installed on port "+port);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the issue to rename a nonexistent file.
  #
  # nb: this check only determines if the code is vulnerable, not whether
  #     the upload directory actually exists, a necessary condition for
  #     exploiting the issue.
  name = "nessus.gif";
  tmp_name = string(SCRIPT_NAME, "-", unixtime());

  w = http_send_recv3(method:"GET", 
    item:string(
      dir, "/mambots/editors/mostlyce/jscripts/tiny_mce/filemanager/connectors/php/connector.php?",
      "Command=FileUpload&",
      "file=a&",
      "file[NewFile][name]=", name, "&",
      "file[NewFile][tmp_name]=", tmp_name, "&",
      "file[NewFile][size]=1&",
      "CurrentFolder="
    ), 
    port:port
  );
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = w[2];

  # There's a problem if we see an error related to the rename operation.
  if (
    string("Error Message: rename(", tmp_name, ",") >< res &&
    string(name, "): No such file or directory <br />") >< res
  )
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
