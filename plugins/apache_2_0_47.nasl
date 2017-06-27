#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11788);
 script_cvs_date("$Date: 2015/10/19 20:19:15 $");
 script_version("$Revision: 1.29 $");

 script_cve_id("CVE-2003-0192", "CVE-2003-0253", "CVE-2003-0254");
 script_bugtraq_id(8134, 8135, 8137, 8138);
 script_osvdb_id(2672, 12557, 12558);
 script_xref(name:"RHSA", value:"2003:243-01");
 script_xref(name:"Secunia", value:"10008");
 script_xref(name:"Secunia", value:"9813");

 script_name(english:"Apache 2.0.x < 2.0.47 Multiple Vulnerabilities (DoS, Encryption)");
 script_summary(english:"Checks version of Apache");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running a version of Apache 2.x prior to
2.0.47. It is, therefore, affected by multiple vulnerabilities :

  - An issue in may occur when the SSLCipherSuite directive
    is used to upgrade a cipher suite which could lead to a
    weaker cipher suite being used instead of the upgraded
    one. (CVE-2003-0192)

  - A denial of service vulnerability may exist in the FTP
    proxy component relating to the use of IPV6 addresses.
    (CVE-2003-0253)

  - An attacker may be able to craft a type-map file that
    could cause the server to enter an infinite loop.
    (CVE-2003-0254)" );
 script_set_attribute(attribute:"see_also", value:"https://archive.apache.org/dist/httpd/CHANGES_2.0" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Apache web server version 2.0.47 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/20");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/07/09");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
 script_end_attributes();
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003-2015 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("apache_http_version.nasl");
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
if (version =~ '^2\\.0' && ver_compare(ver:version, fix:'2.0.47') == -1)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 2.0.47\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "Apache "+version+" is listening on port "+port+" and is not affected.");
