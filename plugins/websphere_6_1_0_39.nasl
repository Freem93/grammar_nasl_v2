#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55649);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/02/22 21:24:29 $");

  script_cve_id("CVE-2011-1209", "CVE-2011-1355", "CVE-2011-1356");
  script_bugtraq_id(47831, 48709, 48710);
  script_osvdb_id(73289, 73898, 73903);

  script_name(english:"IBM WebSphere Application Server 6.1 < 6.1.0.39 Multiple Vulnerabilities");
  script_summary(english:"Reads the version number from the SOAP port");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote application server is affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"IBM WebSphere Application Server 6.1 before Fix Pack 39 appears to be
running on the remote host.  As such, it is potentially affected by
the following vulnerabilities :

  - Use of an insecure XML encryption algorithm could allow
    for decryption of JAX-RPC or JAX-WS Web Services
    requests. (PM34841)

  - An error exists in the validation of the
    'logoutExitPage' parameter that can allow a remote
    attacker to bypass security restrictions and redirect
    users in support of a phishing attack. (PM35701)

  - An error exists in the handling of administration
    console requests. This error can allow a local attacker
    to use a specially crafted request to view sensitive
    stack-trace information. (PM36620)"
  );
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg21404665");
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg27009778");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27007951#61039");
  script_set_attribute(attribute:"solution", value:
"If using WebSphere Application Server, apply Fix Pack 39 (6.1.0.39) or
later. 

Otherwise, if using embedded WebSphere Application Server packaged with
Tivoli Directory Server, apply the latest recommended eWAS fix pack.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");

  script_dependencies("websphere_detect.nasl");
  script_require_ports("Services/www", 8880, 8881);
  script_require_keys("www/WebSphere");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8880, embedded:FALSE);


version = get_kb_item("www/WebSphere/"+port+"/version");
if (isnull(version)) exit(1, "Failed to extract the version from the IBM WebSphere Application Server instance listening on port " + port + ".");
if (version =~ "^[0-9]+(\.[0-9]+)?$")
  exit(1, "Failed to extract a granular version from the IBM WebSphere Application Server instance listening on port " + port + ".");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] == 6 && ver[1] == 1 && ver[2] == 0 && ver[3] < 39)
{
  if (report_verbosity > 0)
  {
    source = get_kb_item_or_exit("www/WebSphere/"+port+"/source");

    report =
      '\n  Source            : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 6.1.0.39' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "The WebSphere Application Server "+version+" instance listening on port "+port+" is not affected.");
