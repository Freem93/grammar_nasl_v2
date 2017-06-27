#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CAN
#
# References:
# Date:  Fri, 29 Jun 2001 13:01:21 -0700 (PDT)
# From: "Extirpater" <extirpater@yahoo.com>
# Subject: 4 New vulns. vWebServer and SmallHTTP
# To: bugtraq@securityfocus.com, vuln-dev@securityfocus.com
#


include("compat.inc");

if(description)
{
 script_id(11071);
 script_version ("$Revision: 1.33 $");
 script_cvs_date("$Date: 2016/10/07 13:30:46 $");

 script_cve_id("CVE-2001-1248", "CVE-2007-3407");
 script_bugtraq_id(2975);
 script_osvdb_id(12403, 32391, 37732, 56515);
 script_xref(name:"Secunia", value:"25809");

 script_name(english:"Multiple Web Server Encoded Space (%20) Request ASP Source Disclosure");
 script_summary(english:"Downloads the source of ASP scripts");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"It appears possible to get the source code of the remote ASP scripts
by appending a '%20' to the request. 

ASP source code usually contains sensitive information such as logins
and passwords.

This has been reported in Simple HTTPD (shttpd), Mono XSP for ASP.NET
and vWebServer. This type of request may affect other web servers as
well." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2006/Dec/326" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2007/Jun/260" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
	
 script_set_attribute(attribute:"plugin_publication_date", value: "2002/08/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/06/29");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");

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

global_var	port;

function check(file)
{
  local_var	r, report;
  r = http_send_recv3(method: "GET", item:string(file, "%20"), port:port, exit_on_fail: 1);
  if (r[0] !~ "^HTTP/.* 200 ") exit(0);

  if ("Content-Type: application/octet-stream" >< r[1])
  {
    if (report_verbosity > 0)
    {
      report = 
        '\n' + "Nessus was able to retrieve the source of '" + file + "' by sending" +
        '\nthe following request :' +
        '\n' +
        '\n  ' + build_url(port:port, qs:file+'%20') + '\n';

      if (report_verbosity > 1)
      {
        local_var res;
        res = r[0] + r[1] + '\r\n';
        if (!isnull(r[2])) res += r[2];

        report += 
          '\nHere is the full response :' +
          '\n' +
          '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + 
          '\n' + res +
          crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
      }
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    return(1);
  }
  if (("<%" >< r[2]) && ("%>" >< r[2])) 
  {
    if (report_verbosity > 0)
    {
      report = 
        '\n' + "Nessus was able to retrieve the source of '" + file + "' by sending" +
        '\nthe following request :' +
        '\n' +
        '\n  ' + build_url(port:port, qs:file+'%20') + '\n';

      if (report_verbosity > 1)
      {
        report += 
          '\nHere it is :' +
          '\n' +
          '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + 
          '\n' + r[2] +
          crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
      }
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    return(1);
  }
 return(0);
}


port = get_http_port(default:80, asp: 1);

if(check(file:"/default.asp"))exit(0);
files = get_kb_list(string("www/", port, "/content/extensions/asp"));
if(isnull(files))exit(0);
files = make_list(files);
check(file:files[0]); 
