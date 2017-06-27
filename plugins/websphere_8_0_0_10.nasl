#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81401);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/24 13:12:23 $");

  script_cve_id(
    "CVE-2013-5704",
    "CVE-2014-0076",
    "CVE-2014-0118",
    "CVE-2014-0226",
    "CVE-2014-0231",
    "CVE-2014-3021",
    "CVE-2014-3070",
    "CVE-2014-3083",
    "CVE-2014-3566",
    "CVE-2014-4764",
    "CVE-2014-4770",
    "CVE-2014-4816",
    "CVE-2014-6166",
    "CVE-2014-6167",
    "CVE-2014-6174"
  );
  script_bugtraq_id(
    66363,
    66550,
    68678,
    68742,
    68745,
    69296,
    69298,
    69301,
    69980,
    69981,
    70239,
    70574,
    70582,
    71836,
    71850
  );
  script_osvdb_id(
    104810,
    105190,
    109216,
    109231,
    109234,
    110185,
    110186,
    110187,
    111737,
    111738,
    113153,
    113251,
    116077,
    116078,
    116079
  );
  script_xref(name:"CERT", value:"577193");

  script_name(english:"IBM WebSphere Application Server 8.0 < Fix Pack 10 Multiple Vulnerabilities (POODLE)");
  script_summary(english:"Reads the version number from the SOAP port.");

  script_set_attribute(attribute:"synopsis", value:"The remote application server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running IBM WebSphere Application Server version
8.0 prior to Fix Pack 10. It is, therefore, affected by the following
vulnerabilities :

  - Multiple errors exist related to the included IBM HTTP
    server that can allow remote code execution or denial
    of service. (CVE-2013-5704, CVE-2014-0118,
    CVE-2014-0226, CVE-2014-0231 / PI22070)

  - An error exists related to the implementation of the
    Elliptic Curve Digital Signature Algorithm (ECDSA) that
    could allow nonce disclosure via the 'FLUSH+RELOAD'
    cache side-channel attack. (CVE-2014-0076 / PI19700)

  - An unspecified error exists related to HTTP headers that
    can allow information disclosure. (CVE-2014-3021 /
    PI08268)

  - An unspecified error caused by improper account creation
    with the Virtual Member Manager SPI Admin Task
    'addFileRegistryAccount' can allow remote attackers to
    bypass security restrictions. (CVE-2014-3070 / PI16765)

  - An information disclosure vulnerability exists due to a
    failure to restrict access to resources located within
    the web application. A remote attacker can exploit this
    to obtain configuration data and other sensitive
    information. (CVE-2014-3083 / PI17768, PI30579 )

  - A man-in-the-middle (MitM) information disclosure
    vulnerability known as POODLE. The vulnerability is due
    to the way SSL 3.0 handles padding bytes when decrypting
    messages encrypted using block ciphers in cipher block
    chaining (CBC) mode. MitM attackers can decrypt a
    selected byte of a cipher text in as few as 256 tries if
    they are able to force a victim application to
    repeatedly send the same data over newly created SSL 3.0
    connections. (CVE-2014-3566 / PI28435, PI28436, PI28437)

  - An unspecified flaw in the Load Balancer for IPv4
    Dispatcher component allows a remote attacker to cause
    a denial of service. (CVE-2014-4764 / PI21189)

  - An unspecified input validation error exists related to
    the administrative console that can allow cross-site
    scripting and cross-site request forgery attacks.
    (CVE-2014-4770, CVE-2014-4816 / PI23055)

  - An error exists related to the Communications Enabled
    Applications (CEA) service that can allow XML External
    Entity Injection (XXE) attacks leading to information
    disclosure. This only occurs if CEA is enabled, and by
    default this is disabled. (CVE-2014-6166 / PI25310)

  - An input validation error exists related to session
    input using URL rewriting that can allow cross-site
    scripting attacks. (CVE-2014-6167 / PI23819)

  - An error exists related to the administrative console
    that can allow click-jacking attacks. (CVE-2014-6174 /
    PI27152)");
  # Downloads
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24039242");
  # Fix list
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27022958#80010");
  # CVE-2014-0226 CVE-2014-0231 CVE-2014-0118 CVE-2013-5704 / PI22070
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21672428");
  # CVE-2014-3566 / PI28438
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21687173");
  # CVE-2014-4770 CVE-2014-4816 / PI23055
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21682767");
  script_set_attribute(attribute:"solution", value:"Apply Fix Pack 10 for version 8.0 (8.0.0.10) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("websphere_detect.nasl");
  script_require_keys("www/WebSphere");
  script_require_ports("Services/www", 8880, 8881);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8880, embedded:0);

app_name = "IBM WebSphere Application Server";

version = get_kb_item_or_exit("www/WebSphere/"+port+"/version");
if (version !~ "^8\.0([^0-9]|$)") audit(AUDIT_NOT_LISTEN,  app_name + " 8.0", port);
if (version =~ "^[0-9]+(\.[0-9]+)?$") audit(AUDIT_VER_NOT_GRANULAR, app_name, port, version);

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] == 8 && ver[1] == 0 && ver[2] == 0 && ver[3] < 10)
{
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  set_kb_item(name: 'www/'+port+'/XSRF', value: TRUE);

  if (report_verbosity > 0)
  {
    source = get_kb_item_or_exit("www/WebSphere/"+port+"/source");
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 8.0.0.10' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);
