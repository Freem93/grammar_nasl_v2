#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(31656);
 script_version("$Revision: 1.21 $");
 script_cvs_date("$Date: 2016/05/04 14:21:28 $");

 script_cve_id(
   "CVE-2005-1268",
   "CVE-2005-2088",
   "CVE-2005-2491",
   "CVE-2005-2700",  
   "CVE-2005-2728", 
   "CVE-2005-2970"
 );
 script_bugtraq_id(
   14106, 
   14366, 
   14620, 
   14660, 
   14721, 
   15762
 );
 script_osvdb_id(
   17738, 
   18286, 
   18906, 
   18977, 
   19188, 
   20462
 );
 
 script_name(english:"Apache < 2.0.55 Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote version of Apache is affected by multiple vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running a version of Apache that is
prior to 2.0.55. It is, therefore affected by multiple
vulnerabilities :

  - A security issue exists where 'SSLVerifyClient' is not
    enforced in per-location context if 'SSLVerifyClient
    optional' is configured in the vhost configuration.
    (CVE-2005-2700)

  - A denial of service vulnerability exists when processing
    a large byte range request, as well as a flaw in the 
    'worker.c' module which could allow an attacker to force
    this service to consume excessive amounts of memory.
    (CVE-2005-2970)

  - When Apache is acting as a proxy, it is possible for a
    remote attacker to poison the web cache, bypass web 
    application firewall protection, and conduct cross-site
    scripting attacks via an HTTP request with both a 
    'Transfer-Encoding: chunked' header and a 
    'Content-Length' header. (CVE-2005-2088)

  - Multiple integer overflows exists in PCRE in quantifier
    parsing which could be triggered by a local user through
    use of a specially crafted regex in an .htaccess file.
    (CVE-2005-2491)

  - An issue exists where the byte range filter buffers
    responses into memory. (CVE-2005-2728)

  - An off-by-one overflow exists in mod_ssl while printing
    CRL information at 'LogLevel debug' which could be 
    triggered if configured to use a 'malicious CRL'.
    (CVE-2005-1268)");

 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e1cae996" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 2.0.55 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2008/03/26");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/07/07");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
script_end_attributes();

 
 summary["english"] = "Checks for version of Apache";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (version =~ '^2\\.0' && ver_compare(ver:version, fix:'2.0.55') == -1)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 2.0.55\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "Apache "+version+" is listening on port "+port+" and is not affected.");
