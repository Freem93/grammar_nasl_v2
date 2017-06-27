#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78604);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/06 17:22:02 $");

  script_cve_id(
    "CVE-2013-5704",
    "CVE-2014-0118",
    "CVE-2014-0226",
    "CVE-2014-0231",
    "CVE-2014-3021",
    "CVE-2014-3083",
    "CVE-2014-4770",
    "CVE-2014-4816"
  );
  script_bugtraq_id(
    66550,
    68678,
    68742,
    68745,
    69298,
    69980,
    69981,
    70582
  );
  script_osvdb_id(
    105190,
    109216,
    109231,
    109234,
    110186,
    111737,
    111738,
    113153
  );
  script_xref(name:"CERT", value:"573356");

  script_name(english:"IBM WebSphere Application Server 7.0 < Fix Pack 35 Multiple Vulnerabilities");
  script_summary(english:"Reads the version number from the SOAP port.");

  script_set_attribute(attribute:"synopsis", value:"The remote application server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of IBM WebSphere Application
Server 7.0 prior to Fix Pack 35. It is, therefore, affected by the
following vulnerabilities :

  - Multiple errors exist related to the included IBM HTTP
    server that could allow remote code execution or denial
    of service. (CVE-2013-5704, CVE-2014-0118,
    CVE-2014-0226, CVE-2014-0231 / PI22070)

  - An error exists related to HTTP header handling that
    could allow the disclosure of sensitive information.
    (CVE-2014-3021 / PI08268)

  - An unspecified error exists that could allow the
    disclosure of sensitive information.
    (CVE-2014-3083 / PI17768)

  - An unspecified input-validation errors exist related to
    the 'Admin Console' that could allow cross-site
    scripting and cross-site request forgery attacks.
    (CVE-2014-4770, CVE-2014-4816 / PI23055)");
  # Advisory
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21684612");
  # Download
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27004980#ver70");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/ibm_security_bulletin_potential_security_vulnerabilities_fixed_in_ibm_websphere_application_server_7_0_0_35?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?834c5fca");
  # APAR PI17768 (Sensitive Info disclosure: CVE-2014-3083)
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg24038178");
  # APAR PI22070 (Multiple vulnerabilities fixed in IBM HTTP Server)
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21672428");
  # APAR PI23055 Sec bulletin for CVE-2014-4770 and CVE-2014-4816 (XSS and XSRF)
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21682767");
  script_set_attribute(attribute:"solution", value:
"Apply Fix Pack 35 (7.0.0.35) or later.

Note that the following interim fixes are available :

  - CVE-2013-5704, CVE-2014-0118, CVE-2014-0226, and
    CVE-2014-0231 are corrected in IF PI22070.
  - CVE-2014-3083 is corrected in IF PI17768.
  - CVE-2014-4770 and CVE-2014-4816 are corrected in
    IF PI23055.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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

version = get_kb_item_or_exit("www/WebSphere/"+port+"/version");
if (version !~ "^7\.0([^0-9]|$)") audit(AUDIT_NOT_LISTEN, "IBM WebSphere Application Server 7.0", port);
if (version =~ "^[0-9]+(\.[0-9]+)?$") audit(AUDIT_VER_NOT_GRANULAR, "IBM WebSphere Application Server", port, version);

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] == 7 && ver[1] == 0 && ver[2] == 0 && ver[3] < 35)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);

  if (report_verbosity > 0)
  {
    source = get_kb_item_or_exit("www/WebSphere/"+port+"/source");
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 7.0.0.35' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "IBM WebSphere Application Server", port, version);
