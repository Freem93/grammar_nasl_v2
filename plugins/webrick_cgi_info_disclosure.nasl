#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31865);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2008-1891");
  script_osvdb_id(44682);
  script_xref(name:"Secunia", value:"29794");

  script_name(english:"WEBrick Encoded Traversal Arbitrary CGI Source Disclosure");
  script_summary(english:"Tries to retrieve source to a CGI");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote instance of WEBrick, a standard library of Ruby to
implement HTTP servers, allows an attacker to view the source of CGI
scripts hosted by the affected application by appending to the URL
certain characters, such as '+', '%2b', '.', '%2e', or '%20'. 

Note that successful exploitation may be dependent on the underlying
remote filesystem, for example FAT32 and NTFS." );
 script_set_attribute(attribute:"see_also", value:"http://aluigi.altervista.org/adv/webrickcgi-adv.txt" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_cwe_id(22);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/04/17");
 script_cvs_date("$Date: 2015/09/24 23:21:22 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

  script_dependencies("webmirror.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

# Unless we're paranoid, make sure the banner looks like WEBrick.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (!banner || "Server: WEBrick/" >!< banner) exit(0);
}


# Identify likely CGI scripts.
cgis = get_kb_list(string("www/", port, "/content/extensions/cgi"));
if (!cgis) exit(0);


# Loop through possible CGIs.
#
# nb: unless thorough_tests is enabled, we'll only scan a couple.
max_cgis = 10;

foreach cgi (cgis)
{
  # Try to exploit the flaw to read its source.
  uri = string(cgi, ".");
  w = http_send_recv3(method:"GET", item:uri, port:port);
  if (isnull(w)) exit(0);
  res = strcat(w[0], w[1], '\r\n', w[2]);

  # If it looks like a CGI.
  if (
    "Content-Type: application/octet-stream" >< w[1] &&
    egrep(pattern:"^#!/[^ ]+/env[ \t]+ruby", string:res)
  )
  {
    # Make sure we can't get the file ordinarily.
    w2 = http_send_recv3(method:"GET", item:cgi, port:port);
    if (isnull(w)) exit(0);
    res2 = strcat(w2[0], w2[1], '\r\n', w2[2]);

    if (!egrep(pattern:"^#!/[^ ]+/env[ \t]+ruby", string:res2))
    {
      if (report_verbosity)
      {
        body = w[2];

        report = string(
          "\n",
          "Nessus was able to retrieve the source for the CGI '", cgi, "'\n",
          "using following URI :\n",
          "\n",
          "  ", uri, "\n",
          "\n",
          "Here are its contents :\n",
          "\n",
          body
        );
        security_warning(port:port, extra:report);
      }
      else security_warning(port);

      exit(0);
    }
  }

  if (!thorough_tests && --max_cgis == 0) break;
}
