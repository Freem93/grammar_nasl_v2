#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(26023);
  script_version("$Revision: 1.37 $");
  script_cvs_date("$Date: 2017/01/30 15:10:02 $");

  script_cve_id("CVE-2006-5752","CVE-2007-1862","CVE-2007-1863","CVE-2007-3303","CVE-2007-3304","CVE-2007-3847","CVE-2007-4465", "CVE-2007-1743");
  script_bugtraq_id(24215, 24553, 24645, 24649, 25489, 25653);
  script_osvdb_id(34872, 37050, 37051, 37052, 37079, 38636, 38641, 38939);

  script_name(english:"Apache 2.2.x < 2.2.6 Multiple Vulnerabilities (DoS, XSS, Info Disc)");
  script_summary(english:"Checks the version in Server response header.");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apache 2.2.x running on the
remote host is prior to 2.2.6. It is, therefore, affected by the
following vulnerabilities :

  - A denial of service vulnerability in mod_proxy. 
  - A cross-site scripting vulnerability in mod_status.
  - A local denial of service vulnerability associated with
    the Prefork MPM module.
  - An information leak in mod_cache.
  - A denial of service vulnerability in mod_cache.

In addition, it offers a workaround for a cross-site scripting issue
in mod_autoindex. 

Note that the remote web server may not actually be affected by these
vulnerabilities. Nessus did not try to determine whether any of the
affected modules are in use on the remote server or to check for the
issues themselves.");
  script_set_attribute(attribute:"see_also", value:"https://archive.apache.org/dist/httpd/CHANGES_2.2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache version 2.2.6 or later. Alternatively, ensure that
the affected modules are not in use.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79, 94);

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");

  script_dependencies("apache_http_version.nasl");
  script_require_keys("www/apache");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

# nb: banner checks of Apache are prone to false-positives so we only
#     run the check if reporting is paranoid.
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
if (version =~ '^2\\.2' && ver_compare(ver:version, fix:'2.2.6') == -1)
{
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);

  if (report_verbosity > 0)
  {
    report = 
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 2.2.6\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "Apache "+version+" is listening on port "+port+" and is not affected.");
