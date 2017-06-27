#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99248);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/04/07 20:05:42 $");

  script_cve_id(
    "CVE-2017-6338",
    "CVE-2017-6339",
    "CVE-2017-6340"
  );
  script_osvdb_id(
    154639,
    154640,
    154641,
    154642,
    154643,
    154644,
    154645,
    154646,
    154648,
    154649,
    154650,
    154652,
    154653,
    154654,
    154655,
    154656,
    154657,
    154658,
    154659,
    154661,
    154662,
    154663,
    154664,
    154665
  );
  script_xref(name:"ZDI", value:"ZDI-17-193");
  script_xref(name:"ZDI", value:"ZDI-17-194");
  script_xref(name:"ZDI", value:"ZDI-17-195");
  script_xref(name:"ZDI", value:"ZDI-17-196");
  script_xref(name:"ZDI", value:"ZDI-17-197");
  script_xref(name:"ZDI", value:"ZDI-17-198");
  script_xref(name:"ZDI", value:"ZDI-17-199");
  script_xref(name:"ZDI", value:"ZDI-17-200");
  script_xref(name:"ZDI", value:"ZDI-17-201");
  script_xref(name:"ZDI", value:"ZDI-17-202");
  script_xref(name:"ZDI", value:"ZDI-17-203");
  script_xref(name:"ZDI", value:"ZDI-17-204");
  script_xref(name:"ZDI", value:"ZDI-17-205");
  script_xref(name:"ZDI", value:"ZDI-17-206");
  script_xref(name:"ZDI", value:"ZDI-17-207");
  script_xref(name:"ZDI", value:"ZDI-17-208");
  script_xref(name:"ZDI", value:"ZDI-17-209");
  script_xref(name:"ZDI", value:"ZDI-17-210");
  script_xref(name:"ZDI", value:"ZDI-17-211");
  script_xref(name:"ZDI", value:"ZDI-17-212");
  script_xref(name:"ZDI", value:"ZDI-17-213");
  script_xref(name:"ZDI", value:"ZDI-17-214");
  script_xref(name:"ZDI", value:"ZDI-17-215");
  script_xref(name:"ZDI", value:"ZDI-17-216");
  script_xref(name:"ZDI", value:"ZDI-17-217");
  script_xref(name:"ZDI", value:"ZDI-17-218");
  script_xref(name:"ZDI", value:"ZDI-17-219");
  script_xref(name:"ZDI", value:"ZDI-17-220");
  script_xref(name:"ZDI", value:"ZDI-17-221");
  script_xref(name:"ZDI", value:"ZDI-17-222");
  script_xref(name:"ZDI", value:"ZDI-17-223");
  script_xref(name:"ZDI", value:"ZDI-17-224");
  script_xref(name:"ZDI", value:"ZDI-17-225");
  script_xref(name:"ZDI", value:"ZDI-17-226");
  script_xref(name:"ZDI", value:"ZDI-17-227");
  script_xref(name:"ZDI", value:"ZDI-17-228");
  script_xref(name:"ZDI", value:"ZDI-17-229");
  script_xref(name:"ZDI", value:"ZDI-17-230");
  script_xref(name:"ZDI", value:"ZDI-17-231");
  script_xref(name:"ZDI", value:"ZDI-17-232");
  script_xref(name:"ZDI", value:"ZDI-17-233");

  script_name(english:"Trend Micro IWSVA 6.5 < 6.5 Build 1746 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Trend Micro IWSVA.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Trend Micro InterScan Web Security Virtual Appliance
(IWSVA) installed on the remote host is 6.5 prior to 6.5 Build 1746.
It is, therefore, affected by multiple vulnerabilities :

  - Multiple access control issues exist that allow an
    authenticated, remote attacker with low privileges to
    modify FTP access control, create or modify reports, or
    upload an HTTPS decryption certificate and private key.
    (CVE-2017-6338)

  - A flaw exists in the management of certain key and
    certificate data. By default, IWSVA acts as a private
    certificate authority (CA) and dynamically generates
    digital certificates that are sent to client browsers
    to complete a secure passage for HTTPS connections.
    It also allows administrators to upload their own
    certificates signed by a root CA. An authenticated,
    remote attacker with low privileges can download the
    current CA certificate and private key (either the
    default ones or ones uploaded by administrators) and use
    those to decrypt HTTPS traffic, resulting in a loss of
    confidentiality. Furthermore, the default private
    key on the appliance is encrypted with a very weak
    passphrase. The attacker can exploit this to likewise
    break the encryption protections. (CVE-2017-6339)

  - An cross-site scripting (XSS) vulnerability exists in
    rest/commonlog/report/template due to improper
    sanitization of user-supplied input to the name field.
    An authenticated, remote attacker with low privileges
    can exploit this to inject arbitrary JavaScript while
    creating a new report. Furthermore, due to incorrect
    access controls, the attacker can exploit this issue to
    create or modify reports, allowing arbitrary script
    code to be executed in a user's browser session when
    the user visits report or auditlog pages.
    (CVE-2017-6340)

  - Additionally, other vulnerabilities have been reported,
    the most serious of which allow an unauthenticated,
    remote attacker to inject commands or execute arbitrary
    code.");
  script_set_attribute(attribute:"see_also", value:"https://success.trendmicro.com/solution/1116960");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-193/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-194/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-195/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-196/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-197/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-198/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-199/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-200/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-201/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-202/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-203/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-204/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-205/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-206/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-207/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-208/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-209/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-210/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-211/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-212/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-213/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-214/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-215/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-216/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-217/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-218/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-219/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-220/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-221/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-222/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-223/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-224/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-225/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-226/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-227/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-228/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-229/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-230/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-231/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-232/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-233/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Trend Micro IWSVA version 6.5 Build 1746 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:trendmicro:interscan_web_security_virtual_appliance");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("trendmicro_iwsva_version.nbin");
  script_require_keys("Host/TrendMicro/IWSVA/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version  = get_kb_item_or_exit("Host/TrendMicro/IWSVA/version");
build    = get_kb_item("Host/TrendMicro/IWSVA/build");

name = "Trend Micro InterScan Web Security Virtual Appliance";

if (empty_or_null(build))
{
  if (report_paranoia > 0) build = "Unknown";
  else exit(0, "The build number of " + name + " could not be determined.");
}

# Apparently only 6.5 is affected
if (version =~ "^6\.5($|[^0-9])")
{
  fix_ver = '6.5';
  fix_build = 1746;
}
else audit(AUDIT_INST_VER_NOT_VULN, name, version, build);

if (build == "Unknown" || build < fix_build)
{
  port = 0;

  order = make_list("Installed version", "Fixed version");
  report = make_array(
    order[0], version + ' Build ' + build,
    order[1], fix_ver + ' Build ' + fix_build
  );

  report = report_items_str(report_items:report, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE, xss:TRUE);
}
else audit(AUDIT_INST_VER_NOT_VULN, name, version, build);
