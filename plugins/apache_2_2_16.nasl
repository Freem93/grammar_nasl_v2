#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(48205);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2016/05/04 14:21:28 $");

  script_cve_id("CVE-2010-1452", "CVE-2010-2068");
  script_bugtraq_id(40827, 41963);
  script_osvdb_id(65654, 66745);
  script_xref(name:"Secunia", value:"40206");

  script_name(english:"Apache 2.2.x < 2.2.16 Multiple Vulnerabilities");
  script_summary(english:"Checks version in Server response header");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apache 2.2.x running on the
remote host is prior to 2.2.16. It is, therefore, potentially affected
by multiple vulnerabilities :

  - A denial of service vulnerability in mod_cache and 
    mod_dav. (CVE-2010-1452)
  
  - An information disclosure vulnerability in mod_proxy_ajp,
    mod_reqtimeout, and mod_proxy_http relating to timeout 
    conditions. Note that this issue only affects Apache on 
    Windows, Netware, and OS/2. (CVE-2010-2068)

Note that the remote web server may not actually be affected by these
vulnerabilities.  Nessus did not try to determine whether the affected
modules are in use or to check for the issues themselves." );

  script_set_attribute(attribute:"see_also", value:"http://httpd.apache.org/security/vulnerabilities_22.html");
  script_set_attribute(attribute:"see_also", value:"https://issues.apache.org/bugzilla/show_bug.cgi?id=49246");
  script_set_attribute(attribute:"see_also", value:"https://issues.apache.org/bugzilla/show_bug.cgi?id=49417");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ce8ac446");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apache version 2.2.16 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("apache_http_version.nasl");
  script_require_keys("www/apache");
  script_require_ports("Services/www", 80);

  exit(0);
}

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
if (version =~ '^2(\\.2)?$') exit(1, "The banner from the Apache server listening on port "+port+" - "+source+" - is not granular enough to make a determination.");
if (version !~ "^\d+(\.\d+)*$") exit(1, "The version of Apache listening on port " + port + " - " + version + " - is non-numeric and, therefore, cannot be used to make a determination.");
if (version =~ '^2\\.2' && ver_compare(ver:version, fix:'2.2.16') == -1)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 2.2.16\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
} 
else exit(0, "Apache "+version+" is listening on port "+port+" and is not affected.");
