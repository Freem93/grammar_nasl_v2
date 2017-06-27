#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(57826);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/02/13 21:07:14 $");

  script_cve_id("CVE-2011-1376");
  script_bugtraq_id(51420,51414);
  script_osvdb_id(78332);

  script_name(english:"IBM WebSphere Application Server Multiple Vulnerabilities");
  script_summary(english:"Reads the version number from the SOAP port");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote application server is susceptible to an insecure file
permission vulnerability, a cross-site scripting attack, and other
unspecified vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of IBM WebSphere application server running on the remote 
host is potentially affected by multiple vulnerabilities :

  - An insecure file permission vulnerability that only affects 
    WebSphere Application Server running on the IBM i 
    platform.  A local attacker may be  able to exploit this 
    issue to obtain potentially sensitive information or 
    modify files in certain  directories. (CVE-2011-1376)

  - Cross-site scripting and other unspecified
    vulnerabilities affecting the z/OS platform."
  );
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24031675");
  script_set_attribute(
    attribute:"solution",
    value:"Apply Fix Pack 43 for 6.1 / 21 for 7.0 / 2 for 8.0 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("os_fingerprint.nasl", "websphere_detect.nasl");
  script_require_ports("Services/www", 8880, 8881);
  script_require_keys("www/WebSphere");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8880, embedded:0);

if (report_paranoia < 2)
{
  os = get_kb_item_or_exit("Host/OS");
  if ("IBM OS/400" >!< os) exit(0, "The issue only affects systems running IBM i and earlier.");
}

version = get_kb_item("www/WebSphere/"+port+"/version");
if (isnull(version)) exit(1, "Failed to extract the version from the IBM WebSphere Application Server instance listening on port " + port + ".");
if (version =~ "^[0-9]+(\.[0-9]+)?$")
  exit(1, "Failed to extract a granular version from the IBM WebSphere Application Server instance listening on port " + port + ".");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

fix = "6.1.0.43";
if (ver[0] == 7)  fix = "7.0.0.21";
else if(ver[0] == 8)  fix = "8.0.0.2";

if (
  (ver[0] == 6 && ver[1] == 1 && ver[2] == 0 && ver[3] < 43) ||
  (ver[0] == 7 && ver[1] == 0 && ver[2] == 0 && ver[3] < 21) ||
  (ver[0] == 8 && ver[1] == 0 && ver[2] == 0 && ver[3] < 2))
{
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  if (report_verbosity > 0)
  {
    source = get_kb_item_or_exit("www/WebSphere/"+port+"/source");

    report = 
      '\n  Source            : ' + source + 
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "The WebSphere Application Server "+version+" instance listening on port "+port+" is not affected.");
