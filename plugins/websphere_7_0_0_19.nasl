#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(56229);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/11/18 21:03:58 $");

  script_cve_id(
    "CVE-2011-1355",
    "CVE-2011-1356",
    "CVE-2011-1359",
    "CVE-2011-1362",
    "CVE-2011-1411"
  );
  script_bugtraq_id(48709, 48710, 48890, 49362);
  script_osvdb_id(73898, 73903, 74167, 74817, 78575);

  script_name(english:"IBM WebSphere Application Server 7.0 < Fix Pack 19 Multiple Vulnerabilities");
  script_summary(english:"Reads the version number from the SOAP port");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote application server may be affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"IBM WebSphere Application Server 7.0 before Fix Pack 19 appears to be
running on the remote host.  As such, it is potentially affected by
the following vulnerabilities :

  - An open redirect vulnerability exists related to the
    'logoutExitPage' parameter. This can allow remote
    attackers to trick users into requesting unintended
    URLs. (PM35701)

  - The administrative console can display a stack trace
    under unspecified circumstances and can disclose
    potentially sensitive information to local users.
    (PM36620)

  - The Installation Verification Tool servlet (IVT) does
    not properly sanitize user-supplied input of arbitrary
    HTML and script code, which could allow cross-site
    scripting attacks. (PM40733)

  - A token verification error exists in the bundled
    OpenSAML library. This error can allow an attacker to
    bypass security controls with an XML signature wrapping
    attack via SOAP messages. (PM43254)

  - A directory traversal attack is possible via unspecified
    parameters in the 'help' servlet. (PM45322)"
  );
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg21404665");
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg27009778");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?rs=180&uid=swg27014463#70019");
  # PM35701 and PM36620
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1PM46122");
  # PM43254
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1PM46125");
  # PM45322
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1PM46125");
  script_set_attribute(attribute:"solution", value:
"If using WebSphere Application Server, apply Fix Pack 19 (7.0.0.19) or
later. 

Otherwise, if using embedded WebSphere Application Server packaged with
Tivoli Directory Server, apply the latest recommended eWAS fix pack.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("websphere_detect.nasl");
  script_require_ports("Services/www", 8880, 8881);
  script_require_keys("www/WebSphere");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:8880, embedded:0);


version = get_kb_item("www/WebSphere/"+port+"/version");
if (isnull(version)) exit(1, "Failed to extract the version from the IBM WebSphere Application Server instance listening on port " + port + ".");
if (version =~ "^[0-9]+(\.[0-9]+)?$")
  exit(1, "Failed to extract a granular version from the IBM WebSphere Application Server instance listening on port " + port + ".");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] == 7 && ver[1] == 0 && ver[2] == 0 && ver[3] < 19)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    source = get_kb_item_or_exit("www/WebSphere/"+port+"/source");

    report =
      '\n  Source            : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 7.0.0.19' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "The WebSphere Application Server "+version+" instance listening on port "+port+" is not affected.");
