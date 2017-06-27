#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2016/04/01. Webmirror3.nbin will identify browsable
# directories.

include("compat.inc");

if(description)
{
 script_id(10511);
 script_version ("$Revision: 1.22 $");
 script_cvs_date("$Date: 2016/12/30 22:07:39 $");

 script_cve_id("CVE-2000-0883");
 script_bugtraq_id(1678);
 script_osvdb_id(410);

 script_name(english:"mod_perl for Apache HTTP Server /perl/ Directory Listing (deprecated)");
 script_summary(english:"Checks if /perl browsable.");
 
 script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
 script_set_attribute(attribute:"description", value:
"The /perl directory is browsable. This will show you the name of the
installed common perl scripts and those that are written by the
webmaster and thus may be exploitable.

This plugin has been deprecated. Webmirror3 (plugin ID 10662) will
identify a browsable directory.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value: "2000/09/11");
 script_set_attribute(attribute:"plugin_publication_date", value: "2000/09/12");
 
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_family(english:"Web Servers");

 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);

 exit(0);
}

# Deprecated.
exit(0, "This plugin has been deprecated. Webmirror3 (plugin ID 10662) will identify a browsable directory.");

#
# The script code starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

r = http_send_recv3(method: "GET", item:"/perl/", port:port);
if (isnull(r)) exit(1, "Server did not answer");

if (" 200 " >< r[0])
{
  buf = tolower(r[2]);
  must_see = "index of /perl";

  if (must_see >< buf)
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/content/directory_index', value: '/perl:');
  }
}

