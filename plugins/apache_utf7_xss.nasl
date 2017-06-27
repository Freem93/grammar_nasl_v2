#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(17696);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/10/07 13:30:46 $");

  script_cve_id("CVE-2008-2168");
  script_bugtraq_id(29112);
  script_osvdb_id(45420);

  script_name(english:"Apache HTTP Server 403 Error Page UTF-7 Encoded XSS");
  script_summary(english:"Checks httpd version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The web server running on the remote host has a cross-site scripting
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the version of Apache HTTP Server running on
the remote host can be used in cross-site scripting (XSS) attacks. 
Making a specially crafted request can inject UTF-7 encoded script
code into a 403 response page, resulting in XSS attacks. 

This is actually a web browser vulnerability that occurs due to
non-compliance with RFC 2616 (refer to BID 29112).  Apache HTTP Server
is not vulnerable, but its default configuration can trigger the
non-compliant, exploitable behavior in vulnerable browsers."
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/May/109");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/May/166");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Apache HTTP Server 2.2.8 / 2.0.63 / 1.3.41 or later. 
These versions use a default configuration setting that prevents
exploitation in vulnerable web browsers."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/05/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

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

# Check if the version looks like either ServerTokens Major/Minor
# was used
if (
  version =~ '^2(\\.2)?$' ||
  version =~ '^2(\\.0)?$' ||
  version =~ '^1(\\.3)?$'
) exit(1, "The banner from the Apache server listening on port "+port+" - "+source+" - is not granular enough to make a determination.");

if (version !~ "^\d+(\.\d+)*$") exit(1, "The version of Apache listening on port " + port + " - " + version + " - is non-numeric and, therefore, cannot be used to make a determination.");

if (version =~ '^2\\.2')
  fixed_ver = '2.2.8';
else if (version =~ '^2\\.0')
  fixed_ver = '2.0.63';
else
  fixed_ver = '1.3.41';

if (ver_compare(ver:version, fix:fixed_ver, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_ver + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "Apache "+version+" is listening on port "+port+" and is not affected.");
