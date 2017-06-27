#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11853);
 script_version("$Revision: 1.28 $");
 script_cvs_date("$Date: 2015/08/04 20:57:13 $");

 script_cve_id("CVE-2003-0789", "CVE-2003-0542");
 script_bugtraq_id(8926);
 script_osvdb_id(2733, 7611, 15889);
 script_xref(name:"Secunia", value:"10096");
 script_xref(name:"Secunia", value:"10845");
 script_xref(name:"Secunia", value:"17311");

 script_name(english:"Apache 2.0.x < 2.0.48 Multiple Vulnerabilities (OF, Info Disc.)");
 script_summary(english:"Checks for version of Apache.");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running a version of Apache 2.0.x prior
to 2.0.48. It is, therefore, affected by multiple vulnerabilities :

  - The mod_rewrite and mod_alias modules fail to handle
    regular expressions containing more than 9 captures
    resulting in a buffer overflow.

  - A vulnerability may occur in the mod_cgid module caused
    by the mishandling of CGI redirect paths. This could
    cause Apache to send the output of a CGI program to the
    wrong client." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/342674/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2004/Jan/msg00000.html" );
 script_set_attribute(attribute:"solution", value:"Upgrade to Apache web server version 2.0.48 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/09/26");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/10/29");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2015 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencies("apache_http_version.nasl");
 script_require_keys("www/apache");
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

# Make sure this is Apache.
get_kb_item_or_exit('www/'+port+'/apache');

# Check if we could get a version first, then check if it was
# backported
version = get_kb_item_or_exit('www/apache/'+port+'/version', exit_code:1);
backported = get_kb_item_or_exit('www/apache/'+port+'/backported', exit_code:1);

if (report_paranoia < 2 && backported) exit(1, "Security Patches may have been backported.");
source = get_kb_item_or_exit('www/apache/'+port+'/source', exit_code:1);

# Check if the version looks like either ServerTokens Major/Minor
# was used
if (version =~ '^2(\\.0)?$') exit(1, "The banner from the Apache server listening on port "+port+" - "+source+" - is not granular enough to make a determination.");
if (version !~ "^\d+(\.\d+)*$") exit(1, "The version of Apache listening on port " + port + " - " + version + " - is non-numeric and, therefore, cannot be used to make a determination.");
if (version =~ '^2\\.0' && ver_compare(ver:version, fix:'2.0.48') == -1)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 2.0.48\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "Apache "+version+" is listening on port "+port+" and is not affected.");
