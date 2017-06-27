#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#

include("compat.inc");

if (description)
{
 script_id(11137);
 script_version("$Revision: 1.39 $");
 script_cvs_date("$Date: 2016/10/07 13:30:46 $");

 script_cve_id("CVE-2002-0839", "CVE-2002-0840", "CVE-2002-0843");
 script_bugtraq_id(5847, 5884, 5887, 5995, 5996);
 script_osvdb_id(862, 4552, 4553);
 
 script_name(english:"Apache < 1.3.27 Multiple Vulnerabilities (DoS, XSS)");
 script_summary(english:"Checks for version of Apache.");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Apache web server prior to
1.3.27. It is, therefore, affected by multiple vulnerabilities :

  - There is a cross-site scripting vulnerability caused by
    a failure to filter HTTP/1.1 'Host' headers that are
    sent by browsers.

  - A vulnerability in the handling of the Apache scorecard
    could allow an attacker to cause a denial of service.

  - A buffer overflow vulnerability exists in the
    'support/ab.c' read_connection() function. The ab.c file
    is a benchmarking support utility that is provided with
    the Apache web server.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Oct/199");
 # https://web.archive.org/web/20040815124139/http://archives.neohapsis.com/archives/vulnwatch/2002-q4/0012.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?767573c2");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Nov/163");
 # https://web.archive.org/web/20071220060323/http://archives.neohapsis.com/archives/vulnwatch/2002-q4/0003.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e06ce83b");
 script_set_attribute(attribute:"solution", value:"Upgrade to Apache web server version 1.3.27 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value:"2002/10/04");
 script_set_attribute(attribute:"vuln_publication_date", value:"2002/10/02");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");
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
get_kb_item('www/'+port+'/apache');

# Check if we could get a version first,  then check if it was
# backported
version = get_kb_item_or_exit('www/apache/'+port+'/version', exit_code:1);
backported = get_kb_item_or_exit('www/apache/'+port+'/backported', exit_code:1);

if (report_paranoia < 2 && backported) exit(1, "Security Patches may have been backported.");
source = get_kb_item_or_exit('www/apache/'+port+'/source', exit_code:1);

# Check if the version looks like either ServerTokens Major/Minor
# was used

if (version =~ '^1(\\.3)?$') exit(1, "The banner from the Apache server listening on port "+port+" - "+source+" - is not granular enough to make a determination.");
if (version !~ "^\d+(\.\d+)*$") exit(1, "The version of Apache listening on port " + port + " - " + version + " - is non-numeric and, therefore, cannot be used to make a determination.");
if (version =~ '^1\\.3' && ver_compare(ver:version, fix:'1.3.27') == -1)
{
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);
  if (report_verbosity > 0)
  {
    report = 
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.3.27\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "Apache "+version+" is listening on port "+port+" and is not affected.");
