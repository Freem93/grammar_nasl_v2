#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(58811);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2016/11/18 20:40:53 $");

  script_cve_id(
    "CVE-2009-0037",
    "CVE-2010-0734",
    "CVE-2010-1452",
    "CVE-2010-1623",
    "CVE-2010-2068",
    "CVE-2010-2791",
    "CVE-2010-3436",
    "CVE-2010-4409",
    "CVE-2010-4645",
    "CVE-2011-0014",
    "CVE-2011-0195",
    "CVE-2011-0419",
    "CVE-2011-1148",
    "CVE-2011-1153",
    "CVE-2011-1464",
    "CVE-2011-1467",
    "CVE-2011-1468",
    "CVE-2011-1470",
    "CVE-2011-1471",
    "CVE-2011-1928",
    "CVE-2011-1938",
    "CVE-2011-1945",
    "CVE-2011-2192",
    "CVE-2011-2202",
    "CVE-2011-2483",
    "CVE-2011-3182",
    "CVE-2011-3189",
    "CVE-2011-3192",
    "CVE-2011-3207",
    "CVE-2011-3210",
    "CVE-2011-3267",
    "CVE-2011-3268",
    "CVE-2011-3348",
    "CVE-2011-3368",
    "CVE-2011-3639",
    "CVE-2011-3846",
    "CVE-2012-0135",
    "CVE-2012-1993"
  );
  script_bugtraq_id(
    33962,
    38162,
    40827,
    41963,
    42102,
    43673,
    44723,
    45119,
    45668,
    46264,
    46843,
    46854,
    46968,
    46969,
    46975,
    46977,
    47668,
    47820,
    47888,
    47929,
    47950,
    48259,
    48434,
    49241,
    49249,
    49303,
    49376,
    49469,
    49471,
    49616,
    49957,
    52974,
    53121
  );
  script_osvdb_id(
    53572,
    62217,
    65654,
    66745,
    68327,
    69110,
    69651,
    70370,
    70847,
    72490,
    72531,
    72532,
    72644,
    73113,
    73218,
    73328,
    73383,
    73388,
    73622,
    73623,
    73625,
    73686,
    73754,
    73755,
    74632,
    74721,
    74726,
    74738,
    74739,
    74742,
    75200,
    75229,
    75230,
    75647,
    76079,
    77444,
    81316,
    81317,
    81318
  );

  script_name(english:"HP System Management Homepage < 7.0 Multiple Vulnerabilities");
  script_summary(english:"Does a banner check");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web server is affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to the web server's banner, the version of HP System
Management Homepage (SMH) hosted on the remote host is earlier than
7.0.  As such, it is reportedly affected by the following
vulnerabilities :

 - An error exists in the 'generate-id' function in the
   bundled libxslt library that can allow disclosure of
   heap memory addresses. (CVE-2011-0195)

 - An unspecified input validation error exists and can
   allow cross-site request forgery attacks. (CVE-2011-3846)

 - Unspecified errors can allow attackers to carry out 
   denial of service attacks via unspecified vectors.
   (CVE-2012-0135, CVE-2012-1993)

 - The bundled version of PHP contains multiple
   vulnerabilities. (CVE-2010-3436, CVE-2010-4409,
   CVE-2010-4645, CVE-2011-1148, CVE-2011-1153,
   CVE-2011-1464, CVE-2011-1467, CVE-2011-1468,
   CVE-2011-1470, CVE-2011-1471, CVE-2011-1938,
   CVE-2011-2202, CVE-2011-2483, CVE-2011-3182,
   CVE-2011-3189, CVE-2011-3267, CVE-2011-3268)

 - The bundled version of Apache contains multiple
   vulnerabilities. (CVE-2010-1452, CVE-2010-1623,
   CVE-2010-2068,  CVE-2010-2791, CVE-2011-0419,
   CVE-2011-1928, CVE-2011-3192, CVE-2011-3348,
   CVE-2011-3368, CVE-2011-3639)

 - OpenSSL libraries are contained in several of the
   bundled components and contain multiple vulnerabilities.
   (CVE-2011-0014, CVE-2011-1468, CVE-2011-1945,
   CVE-2011-3207,CVE-2011-3210)

 - Curl libraries are contained in several of the bundled
   components and contain multiple vulnerabilities.
   (CVE-2009-0037, CVE-2010-0734, CVE-2011-2192)"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.nessus.org/u?a467ff94"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to HP System Management Homepage 7.0 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-14-410");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(352);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/20");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:system_management_homepage");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("compaq_wbem_detect.nasl");
  script_require_keys("www/hp_smh");
  script_require_ports("Services/www", 2301, 2381);

  exit(0);
}


include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port    = get_http_port(default:2381, embedded:TRUE);
install = get_install_from_kb(appname:'hp_smh', port:port, exit_on_fail:TRUE);
dir     = install['dir'];
version = install['ver'];
prod    = get_kb_item_or_exit("www/"+port+"/hp_smh/variant");

if (version == UNKNOWN_VER) 
  exit(1, 'The version of '+prod+' installed at '+build_url(port:port, qs:dir+"/")+' is unknown.');

# nb: 'version' can have non-numeric characters in it so we'll create 
#     an alternate form and make sure that's safe for use in 'ver_compare()'.
version_alt = ereg_replace(pattern:"[_-]", replace:".", string:version);
if (!ereg(pattern:"^[0-9][0-9.]+$", string:version_alt))
  exit(1, 'The version of '+prod+' installed at '+build_url(port:port, qs:dir+"/")+' does not look valid ('+version+').');

fixed_version = '7.0.0.24';
if (ver_compare(ver:version_alt, fix:fixed_version, strict:FALSE) == -1)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);
  if (report_verbosity > 0)
  {
    source_line = get_kb_item("www/"+port+"/hp_smh/source");

    report = '\n  Product           : ' + prod;
    if (!isnull(source_line)) 
      report += '\n  Version source    : ' + source_line;
    report += 
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);

  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, prod, port, version);
