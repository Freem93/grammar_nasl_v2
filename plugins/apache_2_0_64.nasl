#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50069);
  script_cvs_date("$Date: 2017/04/25 14:28:28 $");
  script_version("$Revision: 1.29 $");

  script_cve_id(
    "CVE-2008-2364",
    "CVE-2008-2939",
    "CVE-2009-1891",
    "CVE-2009-2412",
    "CVE-2009-3094",
    "CVE-2009-3095",
    "CVE-2009-3555",
    "CVE-2009-3560",
    "CVE-2009-3720",
    "CVE-2010-0425",
    "CVE-2010-0434",
    "CVE-2010-1452",
    "CVE-2010-1623"
  );
  script_bugtraq_id(29653, 30560, 35949, 38494);
  script_osvdb_id(
    46085,
    47474,
    55782,
    56765,
    56766,
    57851,
    57882,
    59737,
    59969,
    60797,
    62674,
    62675,
    66745,
    68327
  );
  script_xref(name:"Secunia", value:"30261");
  script_xref(name:"Secunia", value:"31384");
  script_xref(name:"Secunia", value:"35781");
  script_xref(name:"Secunia", value:"36549");
  script_xref(name:"Secunia", value:"36675");
  script_xref(name:"Secunia", value:"38776");

  script_name(english:"Apache 2.0.x < 2.0.64 Multiple Vulnerabilities");
  script_summary(english:"Checks version in Server response header");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apache 2.0.x running on the
remote host is prior to 2.0.64. It is, therefore, affected by the
following vulnerabilities :

  - An unspecified error exists in the handling of requests
    without a path segment. (CVE-2010-1452)

  - Several modules, including 'mod_deflate', are 
    vulnerable to a denial of service attack as the
    server can be forced to utilize CPU time compressing
    a large file after client disconnect. (CVE-2009-1891)

  - An unspecified error exists in 'mod_proxy' related to 
    filtration of authentication credentials. 
    (CVE-2009-3095)
 
  - A NULL pointer dereference issue exists in 
    'mod_proxy_ftp' in some error handling paths.
    (CVE-2009-3094)

  - An error exists in 'mod_ssl' making the server
    vulnerable to the TLC renegotiation prefix injection
    attack. (CVE-2009-3555)

  - An error exists in the handling of subrequests such
    that the parent request headers may be corrupted.
    (CVE-2010-0434)

  - An error exists in 'mod_proxy_http' when handling excessive
    interim responses making it vulnerable to a denial of
    service attack. (CVE-2008-2364)

  - An error exists in 'mod_isapi' that allows the module
    to be unloaded too early, which leaves orphaned callback
    pointers. (CVE-2010-0425)

  - An error exists in 'mod_proxy_ftp' when wildcards are
    in an FTP URL, which allows for cross-site scripting
    attacks. (CVE-2008-2939)

Note that the remote web server may not actually be affected by these
vulnerabilities.  Nessus did not try to determine whether the affected
modules are in use or to check for the issues themselves."
  );
  script_set_attribute(attribute:"see_also", value:"https://archive.apache.org/dist/httpd/CHANGES_2.0.64");
  # https://web.archive.org/web/20101028103804/http://httpd.apache.org/security/vulnerabilities_20.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6dea6c32");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache version 2.0.64 or later. Alternatively, ensure that
the affected modules are not in use.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(79, 119, 189, 200, 264, 310, 399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/06/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/20");

  script_set_attribute(attribute:"plugin_type", value: "remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");

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
if (version =~ '^2(\\.0)?$') exit(1, "The banner from the Apache server listening on port "+port+" - "+source+" - is not granular enough to make a determination.");
if (version !~ "^\d+(\.\d+)*$") exit(1, "The version of Apache listening on port " + port + " - " + version + " - is non-numeric and, therefore, cannot be used to make a determination.");
if (version =~ '^2\\.0' && ver_compare(ver:version, fix:'2.0.64') == -1)
{
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);
  if (report_verbosity > 0)
  {
    report = 
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 2.0.64\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "Apache "+version+" is listening on port "+port+" and is not affected.");
