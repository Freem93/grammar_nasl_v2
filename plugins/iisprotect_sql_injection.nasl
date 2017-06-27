#
# (C) Tenable Network Security, Inc.

#
# Note that we need to be authenticated for this check
# to work properly.
#

include("compat.inc");

if(description)
{
 script_id(11662);
 script_version("$Revision: 1.16 $");
 script_cve_id("CVE-2003-0377");
 script_bugtraq_id(7675);
 script_osvdb_id(4931);
 
 script_name(english:"iisPROTECT Admin Interface SiteAdmin.ASP GroupName Parameter SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP application that is affected by
a SQL injection vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running iisPROTECT, an IIS add-on to protect the
pages served by this server. 

There is a bug in the remote version of iisPROTECT that may allow an
attacker with the ability to browse the administrative interface to
execute arbitrary commands through SQL injection on this host." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/322387/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to iisPROTECT version 2.3 or later as that is rumoured to
address the issue." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/28");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/05/23");
 script_cvs_date("$Date: 2011/03/12 01:05:15 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Determines if iisPROTECT is password-protected");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");



port = get_http_port(default:80);

w = http_send_recv3(method:"GET", port:port,
  item:"/iisprotect/admin/SiteAdmin.ASP?V_SiteName=&V_FirstTab=Groups&V_SecondTab=All&GroupName=nessus");
if (isnull(w)) exit(1, "the web server did not answer");
res = strcat(w[0], w[1], '\r_n', w[2]);

if ("Microsoft OLE DB Provider" >< res) exit(0);
 
w = http_send_recv3(method:"GET", port: port,
  item:"/iisprotect/admin/SiteAdmin.ASP?V_SiteName=&V_FirstTab=Groups&V_SecondTab=All&GroupName=nessus'");
if (isnull(w)) exit(1, "the web server did not answer");
res = strcat(w[0], w[1], '\r_n', w[2]);

if("Microsoft OLE DB Provider" >< res)
{
   security_warning(port);
   set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
}
