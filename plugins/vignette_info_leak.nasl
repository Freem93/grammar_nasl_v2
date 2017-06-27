#
# (C) Tenable Network Security, Inc.
#

# Ref:
#  Date: Mon, 07 Apr 2003 12:13:24 -0400
#  From: "@stake Advisories" <advisories@atstake.com>
#  To: bugtraq@securityfocus.com
#  Subject: Vignette Story Server sensitive information disclosure (a040703-1)
#
# Special thanks to Ollie Whitehouse for his help in the writing of this plugin


include("compat.inc");

if(description)
{
 script_id(11526);
 script_version("$Revision: 1.15 $");

 script_bugtraq_id(7296);
 script_osvdb_id(4908);
 script_cve_id("CVE-2002-0385");
 
 script_name(english:"Vignette StoryServer TCL Server Crash Information Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by an
information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Vignette StoryServer, a web 
interface to Vignette's Content Management suite.

A flaw in this product may allow an attacker to extract
information about the other users session and other 
sensitive information." );
 script_set_attribute(attribute:"see_also", value:"http://support.vignette.com/VOLSS/KB/View/1,,5360,00.html" );
 script_set_attribute(attribute:"solution", value:
"Contact vendor for a patch." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/04/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/04/07");
 script_cvs_date("$Date: 2011/03/14 21:48:14 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Checks the version of the remote Vignette StoryServer"); 
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

dirs = get_kb_list(string("www/", port, "/content/directories"));
if(isnull(dirs)) dirs = make_list("");
else dirs = make_list(dirs);

foreach dir (dirs)
{
  res = http_send_recv3(method:"GET", item:string(dir , "/"), port:port);
  if(isnull(res)) exit(1,"Null response to "+ dir + " request.");
  if("Vignette StoryServer" >< res[2]) 
  {
    if(egrep(pattern:"Vignette StoryServer [vV]?[0-4].*", string:res[2]))
      security_warning(port); exit(0);

    if("Vignette StoryServer v6" >< res[2])
       security_warning(port);
    exit(0);
  }
}
