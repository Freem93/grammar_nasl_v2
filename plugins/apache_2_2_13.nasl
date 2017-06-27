#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57603);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/04 14:21:28 $");

  script_cve_id("CVE-2009-2412");
  script_bugtraq_id(35949);
  script_osvdb_id(56765);

  script_name(english:"Apache 2.2.x < 2.2.13 APR apr_palloc Heap Overflow");
  script_summary(english:"Checks version in Server response header");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a buffer overflow
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported banner, the version of Apache 2.2.x
running on the remote host is prior to 2.2.13. As such, it includes a
bundled version of the Apache Portable Runtime (APR) library that
contains a flaw in 'apr_palloc()' that could cause a heap overflow. 

Note that the Apache HTTP server itself does not pass unsanitized,
user-provided sizes to this function so it could only be triggered
through some other application that uses it in a vulnerable way.");
  script_set_attribute(attribute:"see_also", value:"http://httpd.apache.org/security/vulnerabilities_22.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apache 2.2.13 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

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

if (report_paranoia < 2 && backported) exit(1, "Security patches may have been backported.");
source = get_kb_item_or_exit('www/apache/'+port+'/source', exit_code:1);

if (version =~ '^2(\\.2)?$') exit(1, "The banner from the Apache server listening on port "+port+" - "+source+" - is not granular enough to make a determination.");
if (version =~ '^2\\.2' && ver_compare(ver:version, fix:'2.2.13') == -1)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : 2.2.13\n';

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "The Apache version "+version+" server listening on port "+port+" is not affected.");
