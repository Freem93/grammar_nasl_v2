#
# (C) Tenable Network Security, Inc.
#

# Supercedes MS03-019

include("compat.inc");

if (description)
{
 script_id(11664);
 script_version("$Revision: 1.36 $");
 script_cvs_date("$Date: 2016/01/14 15:20:32 $");

 script_cve_id("CVE-2003-0227", "CVE-2003-0349");
 script_bugtraq_id(7727, 8035);
 script_osvdb_id(2106, 4535);
 script_xref(name:"MSFT", value:"MS03-022");

 script_name(english:"Microsoft Media Services ISAPI nsiislog.dll Multiple Overflows");
 script_summary(english:"Determines the presence of nsiislog.dll");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host.");
 script_set_attribute(attribute:"description", value:
"Some versions of IIS shipped with a default file, nsiislog.dll,
within the /scripts directory.  Nessus has determined that the
remote host has the file installed.

The NSIISLOG.dll CGI may allow an attacker to execute
arbitrary commands on this host, through a buffer overflow.");
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms03-022");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Windows 2000.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS03-022 Microsoft IIS ISAPI nsiislog.dll ISAPI POST Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/05/28");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/05/28");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

 script_dependencie("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

b = get_http_banner(port: port, exit_on_fail: 1);
if ("IIS" >!< b ) exit(0);

w  = http_send_recv3(method:"GET", item:"/scripts/nsiislog.dll", port:port, exit_on_fail: 1);
res = strcat(w[0], w[1], '\r\n', w[2]);
if("NetShow ISAPI Log Dll" >< res)
{
  all = make_list("date", "time", "c-dns", "cs-uri-stem", "c-starttime",
  		  "x-duration", "c-rate", "c-status", "c-playerid",
		  "c-playerversion", "c-player-language", "cs(User-Agent)",
		  "cs(Referer)", "c-hostexe");

  poison = NULL;

  foreach litem (all)
  {
   poison += litem + "=Nessus&";
  }

  poison += "c-ip=" + crap(65535);

  w = http_send_recv3(method:"POST", port: port,
    item: "/scripts/nsiislog.dll",
    content_type: "application/x-www-form-urlencoded",
    add_headers: make_array("User-Agent", "NSPlayer/2.0"),
    exit_on_fail: 1, data: poison);
  r = strcat(w[0], w[1], '\r\n', w[2]);

 # 2nd match fails on localized Windows
 if("HTTP/1.1 500 Server Error" >< r && "The remote procedure call failed. " >< r ) security_hole(port);
}
