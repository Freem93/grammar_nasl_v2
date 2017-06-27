#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(66374);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/06 17:22:02 $");

  script_cve_id(
    "CVE-2012-4853",
    "CVE-2013-0169",
    "CVE-2013-0440",
    "CVE-2013-0443",
    "CVE-2013-0458",
    "CVE-2013-0459",
    "CVE-2013-0461",
    "CVE-2013-0462",
    "CVE-2013-0482",
    "CVE-2013-0541",
    "CVE-2013-0542",
    "CVE-2013-0543",
    "CVE-2013-0544"
  );
  script_bugtraq_id(
    56458,
    57508,
    57509,
    57512,
    57513,
    57702,
    57712,
    57778,
    59246,
    59247,
    59248,
    59250,
    59251,
    59252,
    59650
  );
  script_osvdb_id(
    87339,
    89514,
    89515,
    89516,
    89517,
    89802,
    89804,
    89848,
    92711,
    92712,
    92713,
    92714,
    93006
  );

  script_name(english:"IBM WebSphere Application Server 8.0 < Fix Pack 6 Multiple Vulnerabilities");
  script_summary(english:"Reads the version number from the SOAP port");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote application server may be affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"IBM WebSphere Application Server 8.0 before Fix Pack 6 appears to be
running on the remote host.  It is, therefore, potentially affected by
the following vulnerabilities :

  - An input validation error exists that could allow
    cross-site request forgery (CSRF) attacks.
    (CVE-2012-4853 / PM62920)

  - The included Java SDK contains several errors that
    affect the application directly. (CVE-2013-0169,
    CVE-2013-0440, CVE-2013-0443)

  - Input validation errors exist related to the
    administration console that could allow cross-site
    scripting attacks. (CVE-2013-0458 / PM71139,
    CVE-2013-0461 / PM71389, CVE-2013-0542 / PM81846)

  - An input validation error exists related to the
    administration console that could allow cross-site
    scripting attacks. Note that this issue affects only
    the application when running on z/OS operating systems.
    (CVE-2013-0459 / PM72536)

  - An unspecified error could allow security bypass for
    authenticated users. (CVE-2013-0462 / PM76886 or
    PM79937)

  - An error exists related to 'WS-Security' and SOAP
    message handling that could allow an attacker to spoof
    message signatures. (CVE-2013-0482 / PM76582)

  - A buffer overflow error exists related to 'WebSphere
    Identity Manger (WIM)' that could allow denial of
    service attacks. (CVE-2013-0541 / PM74909)

  - An unspecified error could allow security bypass, thus
    allowing remote attackers access to restricted resources
    on HP, Linux and Solaris hosts.
    (CVE-2013-0543 / PM75582)

  - An unspecified error related to the administration
    console could allow directory traversal attacks on
    Unix and Linux hosts. (CVE-2013-0544 / PM82468)"
  );
  # Fix list
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21634646");
  # Relevant Java / WAS bulletin
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21627634");
  # Downloads
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24034673");
  script_set_attribute(attribute:"solution", value:"Apply Fix Pack 6 for version 8.0 (8.0.0.6) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("websphere_detect.nasl");
  script_require_ports("Services/www", 8880, 8881);
  script_require_keys("www/WebSphere");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:8880, embedded:0);


version = get_kb_item_or_exit("www/WebSphere/"+port+"/version");
if (version =~ "^[0-9]+(\.[0-9]+)?$")
  exit(1, "Failed to extract a granular version from the IBM WebSphere Application Server " + version + " instance listening on port " + port + ".");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] == 8 && ver[1] == 0 && ver[2] == 0 && ver[3] < 6)
{
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);
  set_kb_item(name:"www/"+port+"/XSRF", value:TRUE);
  if (report_verbosity > 0)
  {
    source = get_kb_item_or_exit("www/WebSphere/"+port+"/source");
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 8.0.0.6' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "WebSphere", port, version);
