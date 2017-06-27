#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86018);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/08/16 14:42:22 $");

  script_cve_id(
    "CVE-2015-1283",
    "CVE-2015-1788",
    "CVE-2015-1932",
    "CVE-2015-3183",
    "CVE-2015-4938",
    "CVE-2015-4947"
  );
  script_bugtraq_id(
    75158,
    75963,
    75973,
    76463,
    76466,
    76658
  );
  script_osvdb_id(
    122039,
    123122,
    123172,
    126498,
    126500,
    127149
  );
  script_xref(name:"IAVB", value:"2015-B-0115");

  script_name(english:"IBM HTTP Server 6.1 <= 6.1.0.47 (FP47) / 7.0 < 7.0.0.39 (FP39) / 8.0 < 8.0.0.12 (FP12) / 8.5 < 8.5.5.7 (FP7) Multiple Vulnerabilities");
  script_summary(english:"Reads the version number from the SOAP port.");

  script_set_attribute(attribute:"synopsis", value:
"The remote IBM HTTP Server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The IBM HTTP Server running on the remote host is version 6.1 prior
to or equal to 6.1.0.47, 7.0 prior to 7.0.0.39, 8.0 prior to 8.0.0.12,
or 8.5 prior to 8.5.5.7. It is, therefore, potentially affected by
multiple vulnerabilities :

  - An overflow condition exists in the XML_GetBuffer()
    function in xmlparse.c due to improper validation of
    user-supplied input when handling compressed XML
    content. An attacker can exploit this to cause a buffer
    overflow, resulting in the execution of arbitrary code.
    (CVE-2015-1283)

  - A denial of service vulnerability exists when processing
    an ECParameters structure due to an infinite loop that
    occurs when a specified curve is over a malformed binary
    polynomial field. A remote attacker can exploit this to
    perform a denial of service against any system that
    processes public keys, certificate requests, or
    certificates. This includes TLS clients and TLS servers
    with client authentication enabled. (CVE-2015-1788)

  - An information disclosure vulnerability exists that
    allows an unauthenticated, remote attacker to identify
    the proxy server software by reading the HTTP 'Via'
    header. (CVE-2015-1932)

  - A flaw exists in the chunked transfer coding
    implementation due to a failure to properly parse chunk
    headers. A remote attacker can exploit this to conduct
    HTTP request smuggling attacks. (CVE-2015-3183)

  - An unspecified flaw exists that allows an
    unauthenticated, remote attacker to spoof servlets or
    disclose sensitive information. (CVE-2015-4938)

  - An overflow condition exists in the Administration
    Server due to improper validation of user-supplied
    input. An attacker can exploit this, via a specially
    crafted request, to cause a stack-based buffer overflow,
    resulting in a denial of service condition or the
    execution of arbitrary code. (CVE-2015-4947)

Note that :
  - CVE-2015-1788 does not affect the 6.1 and 7.0 branches.
  
  - CVE-2015-1932 and CVE-2015-4938 do not affect the 6.1
    branch.");
  # CVE-2015-3183 / PI42928 / PI45596 (6.1.x)
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21963361");
  # CVE-2015-4947 / PI44793 / PI45596 (6.1.x)
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21965419");
  # CVE-2015-1788 / PI44809
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21963362");
  # CVE-2015-1283 / PI45596
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21964428");
  # CVE-2015-1932 / PI38403  and  CVE-2015-4938 / PI37396
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21963275");
  script_set_attribute(attribute:"solution", value:
"Apply IBM 7.0 Fix Pack 39 (7.0.0.39) / 8.0 Fix Pack 12 (8.0.0.12) /
8.5 Fix Pack 7 (8.5.5.7) or later. Alternatively, apply the Interim
Fixes as recommended in the vendor advisory.

In the case of the 6.1 branch, apply IBM 6.1 Fix Pack 47 (6.1.0.47)
and then apply Interim Fixes PI39833 and PI45596.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/18");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:http_server");

  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("websphere_detect.nasl");
  script_require_ports("Services/www", 8880, 8881);
  script_require_keys("www/WebSphere", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:8880, embedded:0);

version = get_kb_item_or_exit("www/WebSphere/"+port+"/version");
source = get_kb_item_or_exit("www/WebSphere/"+port+"/source");

app_name = "IBM WebSphere Application Server";

if (version =~ "^[0-9]+(\.[0-9]+)?$")
  audit(AUDIT_VER_NOT_GRANULAR, app_name, port, version);

fix  = FALSE; # Fixed version for compare
min  = FALSE; # Min version for branch
pck  = FALSE; # Fix pack name (tacked onto fix in report)
itr  = "PI42928, PI44793, PI44809 and PI45596"; # Required interim fixes
vuln = FALSE; # Flag for branches requiring <= checks

if (version =~ "^8\.5\.")
{
  fix = '8.5.5.7';
  min = '8.5.0.0';
  itr = 'PI37396, PI38403, ' + itr;
  pck = " (Fix Pack 7)";
}
else if (version =~ "^8\.0\.")
{
  fix = '8.0.0.12';
  min = '8.0.0.0';
  pck = " (Fix Pack 12) Available 2016/01/18";
}
else if (version =~ "^7\.0\.")
{
  fix = '7.0.0.39';
  min = '7.0.0.0';
  itr = 'PI37396, PI38403, ' + itr;
  pck = " (Fix Pack 39)";
}

# V6.1.0.0 through 6.1.0.47 (without PI45596)
else if (version =~ "^6\.1\.")
{
  if (ver_compare(ver:version, fix:'6.1.0.47', strict:FALSE) <= 0)
  {
    fix = '6.1.0.47';
    min = '6.1.0.0';
    pck = " (Fix Pack 47) plus PI45596";
    vuln = TRUE;
  }
}

if (
    (
      fix && min &&
      ver_compare(ver:version, fix:fix, strict:FALSE) <  0 &&
      ver_compare(ver:version, fix:min, strict:FALSE) >= 0
    )
    ||
    vuln
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + source  +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + pck +
      '\n  Interim fixes     : ' + itr +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);
