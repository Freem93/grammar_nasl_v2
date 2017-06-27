#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(14230);
 script_version ("$Revision: 1.22 $");
 script_cve_id("CVE-2004-2624");
 script_bugtraq_id(10860);
 script_xref(name:"OSVDB", value:"8295");

 script_name(english:"WackoWiki TextSearch phrase Parameter XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI application that is prone to a
cross-site scripting attack." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running the WackoWiki CGI suite. 

Based on the version information gathered by Nessus, this instance of
WackoWiki may be vulnerable to a remote authentication attack. 

Exploitation of this vulnerability may allow for theft of cookie-based
authentication credentials and cross-site scripting attacks." );
 script_set_attribute(attribute:"see_also", value:"http://wackowiki.com/WackoDownload/VersionHistory?v=yrv#h9241-2" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WackoWiki version R4 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/09");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/08/04");
 script_cvs_date("$Date: 2015/01/16 03:36:09 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "Checks for WackoWiki XSS flaw";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("cross_site_scripting.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

test_cgi_xss(port: port, cgi: "/WackoWiki", dirs: cgi_dirs(),
 pass_re: "Powered by .*WackoWiki R3\.5");
