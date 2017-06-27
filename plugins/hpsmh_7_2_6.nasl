#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90251);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/04/01 15:48:36 $");

  script_cve_id(
    "CVE-2014-0015",
    "CVE-2014-0138",
    "CVE-2014-0139",
    "CVE-2014-2522",
    "CVE-2014-2641",
    "CVE-2014-3569",
    "CVE-2014-3570",
    "CVE-2014-3571",
    "CVE-2014-3572",
    "CVE-2014-8275",
    "CVE-2015-0204",
    "CVE-2015-0205",
    "CVE-2015-0206",
    "CVE-2015-0207",
    "CVE-2015-0208",
    "CVE-2015-0209",
    "CVE-2015-0285",
    "CVE-2015-0286",
    "CVE-2015-0287",
    "CVE-2015-0288",
    "CVE-2015-0289",
    "CVE-2015-0290",
    "CVE-2015-0291",
    "CVE-2015-0292",
    "CVE-2015-0293",
    "CVE-2015-1788",
    "CVE-2015-1789",
    "CVE-2015-1790",
    "CVE-2015-1791",
    "CVE-2015-1792",
    "CVE-2015-3143",
    "CVE-2015-3145",
    "CVE-2015-3148"
  );
  script_bugtraq_id(
    65270,
    66296,
    66457,
    66458,
    70208,
    71934,
    71935,
    71936,
    71937,
    71939,
    71940,
    71941,
    71942,
    73225,
    73226,
    73227,
    73228,
    73229,
    73230,
    73231,
    73232,
    73234,
    73235,
    73237,
    73239,
    74299,
    74301,
    74303,
    75154,
    75156,
    75157,
    75158,
    75161
  );
  script_osvdb_id(
    102715,
    104972,
    105009,
    104974,
    112411,
    116423,
    116796,
    116793,
    116795,
    116792,
    116794,
    116790,
    116791,
    119760,
    119759,
    118817,
    119673,
    119761,
    119755,
    119328,
    119756,
    119758,
    119692,
    119743,
    119757,
    123172,
    123173,
    123174,
    122875,
    123175,
    121128,
    121130,
    121129
  );
  script_xref(name:"CERT", value:"243585");
  script_xref(name:"HP", value:"HPSBMU03422");
  script_xref(name:"HP", value:"emr_na-c04805275");
  script_xref(name:"HP", value:"SSRT101438");
  script_xref(name:"HP", value:"SSRT101447");
  script_xref(name:"HP", value:"SSRT102109");

  script_name(english:"HP System Management Homepage < 7.2.6 Multiple Vulnerabilities (FREAK)");
  script_summary(english:"Checks version in the banner.");

  script_set_attribute(attribute:"synopsis", value:"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to the web server's banner, the version of HP System
Management Homepage (SMH) hosted on the remote web server is prior to
7.2.6. It is, therefore, affected by multiple vulnerabilities,
including remote code execution vulnerabilities, in several components
and third-party libraries :

  - HP SMH (XSRF)
    - libcurl
    - OpenSSL");
  # http://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c04805275
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?12cb3f9e");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20150108.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.smacktls.com/#freak");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20150319.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to HP System Management Homepage (SMH) version 7.2.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:system_management_homepage");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:haxx:curl");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:haxx:libcurl");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("compaq_wbem_detect.nasl");
  script_require_keys("www/hp_smh");
  script_require_ports("Services/www", 2301, 2381);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

get_kb_item_or_exit("www/hp_smh");

port    = get_http_port(default:2381, embedded:TRUE);

install = get_install_from_kb(appname:'hp_smh', port:port, exit_on_fail:TRUE);
dir     = install['dir'];
version = install['ver'];
prod    = get_kb_item_or_exit("www/"+port+"/hp_smh/variant");

if (version == UNKNOWN_VER) exit(1, 'The version of '+prod+' installed at '+build_url(port:port, qs:dir+"/")+' is unknown.');

# nb: 'version' can have non-numeric characters in it so we'll create
#     an alternate form and make sure that's safe for use in 'ver_compare()'.
version_alt = ereg_replace(pattern:"[_-]", replace:".", string:version);
if (!ereg(pattern:"^[0-9][0-9.]+$", string:version_alt)) exit(1, 'The version of '+prod+' installed at '+build_url(port:port, qs:dir+"/")+' does not look valid ('+version+').');

fixed_version = '7.2.6';
if (ver_compare(ver:version_alt, fix:fixed_version, strict:FALSE) == -1)
{
  source_line = get_kb_item("www/"+port+"/hp_smh/source");

  report = '\n  Product           : ' + prod;
  if (!isnull(source_line))
    report += '\n  Version source    : ' + source_line;
  report +=
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fixed_version +
    '\n';

  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report, xsrf:TRUE);
}
else audit(AUDIT_LISTEN_NOT_VULN, prod, port, version);
