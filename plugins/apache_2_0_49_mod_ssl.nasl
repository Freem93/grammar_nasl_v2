#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(12100);
 script_version("$Revision: 1.24 $");
 script_cvs_date("$Date: 2015/08/04 20:57:13 $");

 script_cve_id("CVE-2004-0113");
 script_bugtraq_id(9826);
 script_osvdb_id(4182);
 script_xref(name:"Secunia", value:"11092");
 script_xref(name:"Secunia", value:"11705");

 script_name(english:"Apache 2.0.x < 2.0.49 mod_ssl Plain HTTP Request DoS");
 script_summary(english:"Checks for version of Apache.");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a denial of service
vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running a version of Apache 2.0.x prior
to 2.0.49. It is, therefore, affected by a denial of service
vulnerability in the 'mod_ssl' module. An attacker can exploit this to
deny service to the Apache server.");
 script_set_attribute(attribute:"solution", value:"Upgrade to Apache web server version 2.0.49 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/02/20");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/03/14");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

 script_dependencie("apache_http_version.nasl");
 script_require_keys("www/apache");
 script_require_ports("Services/www", 443);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:443);

# Make sure this is Apache.
get_kb_item_or_exit('www/'+port+'/apache');

transport = get_port_transport(port);

if ( ! ( transport == ENCAPS_SSLv23 ||
	 transport == ENCAPS_SSLv2 ||
	 transport == ENCAPS_SSLv3 ||
	 transport == ENCAPS_TLSv1) ) exit(0, "The Apache server on port "+port+" does not appear to be using SSL");

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
if (version =~ '^2\\.0' && ver_compare(ver:version, fix:'2.0.49') == -1)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 2.0.49\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "Apache "+version+" is listening on port "+port+" and is not affected.");
