#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31787);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2008-0872");
  script_bugtraq_id(27878);
  script_osvdb_id(41857);
  script_xref(name:"Secunia", value:"29024");

  script_name(english:"SmarterMail Subject Field XSS");
  script_summary(english:"Checks version in online help link");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP application that is affected by
a cross-site scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running SmarterMail, an email and collaboration
server for Windows. 

The webmail component of the version of SmarterMail installed on the
remote host fails to sanitize the Subject field of messages before
using it to generate dynamic HTML output.  An unauthenticated attacker
may be able to exploit this to inject arbitrary HTML and script code
into a user's browser to be executed within the security context of
the affected site." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/488313/100/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.smartertools.com/products/smartermail/ReleaseNotesV4.aspx" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 4.3.2981 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(79);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/04/07");
 script_cvs_date("$Date: 2016/05/13 15:33:30 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/ASP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);
if (!can_host_asp(port:port)) exit(0);

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/smartermail", "/webmail", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Grab the login form.
  w = http_send_recv3(method:"GET", item:string(dir, "/Login.aspx"), port:port);
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = w[2];

  # Get the version.
  if (
    "SmarterMail Login" >< res &&
    "/Help/SmarterMail" >< res &&
    "/Default.aspx?p=USR&amp;v=" >< res
  )
  {
    ver = strstr(res, "/Default.aspx?p=USR&amp;v=") - "/Default.aspx?p=USR&amp;v=";
    if ('&amp;page=LoginUser' >< ver) ver = ver - strstr(ver, '&amp;page=LoginUser');
    else ver = NULL;

    if (!isnull(ver) && ver =~ "^[0-9][0-9.]+[0-9]$")
    {
      iver = split(ver, sep:'.', keep:FALSE);
      for (i=0; i<max_index(iver); i++)
        iver[i] = int(iver[i]);

      if (
        iver[0] < 4 ||
        (
          iver[0] == 4 &&
          (
            iver[1] < 3 ||
            (iver[1] == 3 && iver[2] < 2981)
          )
        )
      )
      {
        if (report_verbosity)
        {
          report = string(
            "\n",
            "The remote host is running SmarterMail version ", ver, ".\n"
          );
          security_warning(port:port, extra:report);
        }
        else security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
        exit(0);
      }
    }
  }
}
