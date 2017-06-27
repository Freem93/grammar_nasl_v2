#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81825);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/24 13:12:23 $");

  script_cve_id(
    "CVE-2014-3566",
    "CVE-2014-6167",
    "CVE-2014-6174",
    "CVE-2014-6457",
    "CVE-2014-6512",
    "CVE-2014-6558",
    "CVE-2014-6593",
    "CVE-2015-0400",
    "CVE-2015-0410"
  );
  script_bugtraq_id(
    70239,
    70538,
    70544,
    70567,
    70574,
    71850,
    72159,
    72165,
    72169
  );
  script_osvdb_id(
    99712,
    113251,
    113333,
    113337,
    116078,
    116079,
    117236,
    117238,
    117239
  );
  script_xref(name:"CERT", value:"577193");

  script_name(english:"IBM WebSphere Application Server 7.0 < Fix Pack 37 Multiple Vulnerabilities (POODLE)");
  script_summary(english:"Reads the version number from the SOAP port.");

  script_set_attribute(attribute:"synopsis", value:
"The remote application server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The IBM WebSphere Application Server running on the remote host is
version 7.0 prior to Fix Pack 37. It is, therefore, affected by the
following vulnerabilities :

  - A man-in-the-middle (MitM) information disclosure
    vulnerability known as POODLE. The vulnerability is due
    to the way SSL 3.0 handles padding bytes when decrypting
    messages encrypted using block ciphers in cipher block
    chaining (CBC) mode. MitM attackers can decrypt a
    selected byte of a cipher text in as few as 256 tries if
    they are able to force a victim application to
    repeatedly send the same data over newly created SSL 3.0
    connections. (CVE-2014-3566 / PI27101)

  - An input validation error exists related to session
    input using URL rewriting that can allow cross-site
    scripting attacks. (CVE-2014-6167 / PI23819)

  - An error exists related to the administrative console
    that can allow 'click-jacking' attacks.
    (CVE-2014-6174 / PI27152)

  - Multiple errors exist in the bundled IBM Java SDK. These
    errors are corrected by the October 2014 IBM Java SDK
    updates. (CVE-2014-6457, CVE-2014-6512, CVE-2014-6558 /
    PI27101)

  - Multiple errors exist in the bundled IBM Java SDK. These
    errors are corrected by the January 2015 IBM Java SDK
    updates. (CVE-2014-6593, CVE-2015-0400, CVE-2015-0410) /
    PI33407");
  # Fix list
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27014463#70037");
  # Download
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24039338");
  # IBM Java SDK / OCT 2014
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21687740");
  # IBM Java SDK / JAN 2015
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21695362");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/ssl-poodle.pdf");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00");
  script_set_attribute(attribute:"solution", value:
"Apply Fix Pack 37 (7.0.0.37) or later.

Note that interim fixes are available. Refer to the vendor security
advisory for interim fix identifiers.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/17");

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

port    = get_http_port(default:8880, embedded:0);
version = get_kb_item_or_exit("www/WebSphere/"+port+"/version");

app_name = "IBM WebSphere Application Server";

if (version !~ "^7\.0([^0-9]|$)") audit(AUDIT_NOT_LISTEN, app_name + " 7.0", port);
if (version =~ "^[0-9]+(\.[0-9]+)?$") audit(AUDIT_VER_NOT_GRANULAR, app_name, port, version);

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] == 7 && ver[1] == 0 && ver[2] == 0 && ver[3] < 37)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    source = get_kb_item_or_exit("www/WebSphere/"+port+"/source");
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 7.0.0.37' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);
