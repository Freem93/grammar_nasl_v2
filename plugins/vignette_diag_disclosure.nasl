#
# (C) Tenable Network Security
#

# Thanks to Cory Scott from @stake for his help during the 
# writing of this plugin


include("compat.inc");

if(description)
{
 script_id(14847);
 script_version("$Revision: 1.10 $");
 script_cve_id("CVE-2004-0917");
 script_bugtraq_id(11267);
 script_osvdb_id(10405);
 
 script_name(english:"Vignette Application Portal Diagnostic Utility Information Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by an 
information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Vignette Application Portal, a 
commercially available portal suite.

There is an information disclosure vulnerability in the 
remote version of this software. An attacker can request the 
diagnostic utility which will disclose information about the 
remote site by requesting /portal/diag/." );
 script_set_attribute(attribute:"solution", value:
"Restrict access to the diag directory." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/29");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/09/28");
 script_cvs_date("$Date: 2011/03/13 23:54:24 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "Request /portal/diag"; 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
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
  res = http_send_recv3(method:"GET", item:string(dir , "/portal/diag/index.jsp"), port:port);
  if( isnull(res) ) exit(1,"Null response to index.jsp request.");
  if("Vignette Application Portal Diagnostic Report" >< res[2])
  {
   security_warning(port);
  }
}
