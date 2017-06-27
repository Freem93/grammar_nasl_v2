#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(19596); 
 script_version("$Revision: 1.10 $");
 script_cve_id("CVE-2000-0778");
 script_bugtraq_id(14764);
 script_osvdb_id(390);
 name["english"] = "Microsoft IIS Translate f: ASP/ASA Source Disclosure (IIS 5.1)";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a 
source code disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"There is a serious vulnerability in IIS 5.1 that allows 
an attacker to view ASP/ASA source code instead of a 
processed file, when the files are stored on a FAT 
partition.

ASP source code can contain sensitive information such as
username's and passwords for ODBC connections." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?81d0b19f" );
 script_set_attribute(attribute:"solution", value:
"Install the remote web server on a NTFS partition" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/09/08");
 script_set_attribute(attribute:"patch_publication_date", value: "2000/08/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/08/15");
 script_cvs_date("$Date: 2011/12/01 23:27:32 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 summary["english"] = "downloads the source of IIS scripts such as ASA,ASP";
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");

port = get_http_port(default:80);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);

files = get_kb_list(string("www/", port, "/content/extensions/asp"));
if(isnull(files))exit(0);

files = make_list(files);
 
file = str_replace(string:files[0], find:".asp", replace:".as%CF%80");
res = http_send_recv3(method:"GET", item:file, port:port,
         add_headers: make_array("Translate", "f"));
  
if(isnull(res)) exit(0);
if("Content-Type: application/octet-stream" >< res[2])
{
  res = http_send_recv3(method:"GET", item:files[0], port:port);
  if ( "Content-Type: application/octet-stream" >!< res[2] ) security_warning(port);
}
