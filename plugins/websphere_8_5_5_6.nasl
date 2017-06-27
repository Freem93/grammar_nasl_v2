#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84639);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/12/12 18:38:06 $");

  script_cve_id(
    "CVE-2015-0138",
    "CVE-2015-0226",
    "CVE-2015-0250",
    "CVE-2015-1885",
    "CVE-2015-1927",
    "CVE-2015-1932",
    "CVE-2015-1936",
    "CVE-2015-1946",
    "CVE-2015-2808",
    "CVE-2015-4938"
  );
  script_bugtraq_id(
    72553,
    73326,
    73684,
    74219,
    75480,
    75486,
    75496,
    76463,
    76466
  );
  script_osvdb_id(
    89579,
    90591,
    117855,
    119390,
    119704,
    123826,
    123827,
    123828,
    126498,
    126500
  );
  script_xref(name:"CERT", value:"243585");

  script_name(english:"IBM WebSphere Application Server 7.0 < 7.0.0.39 (FP39) / 8.0 < 8.0.0.11 (FP11) / 8.5 < 8.5.5.6 (FP6) Multiple Vulnerabilities (Bar Mitzvah) (FREAK)");
  script_summary(english:"Reads the version number from the SOAP port.");

  script_set_attribute(attribute:"synopsis", value:
"The remote application server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The IBM WebSphere Application Server running on the remote host is
version 7.0 prior to 7.0.0.39, 8.0 prior to 8.0.0.11, or 8.5 prior to
8.5.5.6. It is, therefore, potentially affected by multiple
vulnerabilities :

  - A security feature bypass vulnerability, known as FREAK
    (Factoring attack on RSA-EXPORT Keys), exists in the IBM
    Global Security Kit (GSKit) due to the support of weak
    EXPORT_RSA cipher suites with keys less than or equal to
    512 bits. A man-in-the-middle attacker may be able to
    downgrade the SSL/TLS connection to use EXPORT_RSA
    cipher suites which can be factored in a short amount of
    time, allowing the attacker to intercept and decrypt the
    traffic. (CVE-2015-0138)

  - An information disclosure vulnerability exists due to a
    flaw in the Bleichenbacher countermeasure implementation 
    in Apache WSS4J. A remote attacker can exploit this, via
    a crafted message, to determine where an encryption
    failure to place, allowing the attacker to gain access
    to the plaintext symmetric key. (CVE-2015-0226)

  - An XML External Entity (XXE) vulnerability exists due to
    an incorrectly configured XML parser that accepts XML
    external entities from an untrusted source. A remote
    attacker can exploit this, via specially crafted XML
    data, to gain access to arbitrary files. (CVE-2015-0250)

  - A privilege escalation vulnerability exists due to a
    flaw that occurs in 'full' profile and 'liberty' profile
    when using an OAuth grant password. A remote attacker
    can exploit this to gain elevated privileges.
    (CVE-2015-1885)

  - A privilege escalation vulnerability exists due to
    incorrect settings in the serveServletsbyClassname
    functionality. A remote attacker can exploit this to
    gain elevated privileges. (CVE-2015-1927)

  - An information disclosure vulnerability exists that
    allows an unauthenticated, remote attacker to identify
    the proxy server software by reading the HTTP 'Via'
    header. (CVE-2015-1932)

  - An unspecified flaw exists in the administrative console
    that allows a remote attacker, via the 'JSESSIONID'
    parameter, to hijack a user's session. (CVE-2015-1936)

  - A privilege escalation vulnerability exists due to an
    unspecified flaw that occurs when handling user roles.
    A local attacker can exploit this to gain elevated
    privileges. (CVE-2015-1946)
  
  - A security feature bypass vulnerability exists, known as
    Bar Mitzvah, due to improper combination of state data
    with key data by the RC4 cipher algorithm during the
    initialization phase. A man-in-the-middle attacker can
    exploit this, via a brute-force attack using LSB values,
    to decrypt the traffic. (CVE-2015-2808)

  - An unspecified flaw exists that allows an
    unauthenticated, remote attacker to spoof servlets or
    disclose sensitive information. (CVE-2015-4938)");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21698613");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21959083");
  script_set_attribute(attribute:"see_also", value:"http://www-304.ibm.com/support/docview.wss?uid=swg27004980");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21963275");
  # https://www.blackhat.com/docs/asia-15/materials/asia-15-Mantin-Bar-Mitzvah-Attack-Breaking-SSL-With-13-Year-Old-RC4-Weakness-wp.pdf
  script_set_attribute(attribute:"see_also", value:"https://www.smacktls.com/#freak");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4bbf45ac");
  script_set_attribute(attribute:"solution", value:
"Apply IBM 7.0 Fix Pack 39 (7.0.0.39) / 8.0 Fix Pack 11 (8.0.0.11) /
8.5 Fix Pack 6 (8.5.5.6) or later. Alternatively, apply the Interim
Fixes as recommended in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/09");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");

  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

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

fix = FALSE; # Fixed version for compare
min = FALSE; # Min version for branch
pck = FALSE; # Fix pack name (tacked onto fix in report)
itr = "PI36563, PI36211, PI39768, PI31622, PI37230, and PI35180"; # Required interim fixes

if (version =~ "^8\.5\.")
{
  fix = '8.5.5.6';
  min = '8.5.0.0';
  # CVE-2015-0226 only 8.5.5.2 - 8.5.5.5
  # has an additional interim fix.
  if(version =~ "^8\.5\.5\.[2-5]$")
    itr = 'PI36866, ' + itr;
  pck = " (Fix Pack 6)";
}
else if (version =~ "^8\.0\.")
{
  fix = '8.0.0.11';
  min = '8.0.0.0';
  itr = 'PI37396, PI38403, ' + itr;
  pck = " (Fix Pack 11)";
}
else if (version =~ "^7\.0\.")
{
  fix = '7.0.0.39';
  min = '7.0.0.0';
  itr = 'PI37396, PI38403, ' + itr;
  pck = " (Fix Pack 39)";
}

if (fix && min &&
    ver_compare(ver:version, fix:fix, strict:FALSE) <  0 &&
    ver_compare(ver:version, fix:min, strict:FALSE) >= 0
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
