#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42052);
  script_cvs_date("$Date: 2016/11/11 19:58:29 $");
  script_version("$Revision: 1.27 $");

  script_cve_id("CVE-2009-2699", "CVE-2009-3094", "CVE-2009-3095");
  script_bugtraq_id(36254, 36260, 36596);
  script_osvdb_id(57851, 57882, 58879);
  script_xref(name:"Secunia", value:"36549");

  script_name(english:"Apache 2.2.x < 2.2.14 Multiple Vulnerabilities");
  script_summary(english:"Checks version in Server response header.");

  script_set_attribute(attribute:"synopsis", value:
    "The remote web server is affected by multiple vulnerabilities."
  );
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apache 2.2.x running on the 
remote host is prior to 2.2.14. It is, therefore, potentially affected
by multiple vulnerabilities :

  - Faulty error handling in the Solaris pollset support 
    could lead to a denial of service. (CVE-2009-2699)

  - The 'mod_proxy_ftp' module allows remote attackers to 
    bypass intended access restrictions. (CVE-2009-3095)

  - The 'ap_proxy_ftp_handler' function in 
    'modules/proxy/proxy_ftp.c' in the 'mod_proxy_ftp' 
    module allows remote FTP servers to cause a 
    denial of service. (CVE-2009-3094)

Note that the remote web server may not actually be affected by these
vulnerabilities as Nessus did not try to determine whether the affected
modules are in use or check for the issues themselves."  );

  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/17947");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/17959");
  # http://web.archive.org/web/20100106104919/http://wiki.rpath.com/wiki/Advisories:rPSA-2009-0154
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e470f137");
  script_set_attribute(attribute:"see_also", value:"https://issues.apache.org/bugzilla/show_bug.cgi?id=47645");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c34c4eda");

  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache version 2.2.14 or later. Alternatively, ensure that
the affected modules are not in use.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("apache_http_version.nasl");
  script_require_keys("www/apache");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("http.inc");
include("misc_func.inc");

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
if (version =~ '^2\\.2' && ver_compare(ver:version, fix:'2.2.14') == -1)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 2.2.14\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "Apache "+version+" is listening on port "+port+" and is not affected.");
