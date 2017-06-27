#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(65255);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/21 22:04:45 $");

  script_cve_id(
    "CVE-2012-5200",
    "CVE-2012-5201",
    "CVE-2012-5202",
    "CVE-2012-5203",
    "CVE-2012-5204",
    "CVE-2012-5205",
    "CVE-2012-5206",
    "CVE-2012-5207",
    "CVE-2012-5208",
    "CVE-2012-5209",
    "CVE-2012-5212",
    "CVE-2012-5213"
  );
  script_bugtraq_id(
    58293, 
    58672, 
    58673, 
    58675, 
    58676, 
    58677,
    58965,
    58966,
    58968,
    58969,
    58970,
    58972,
    58973
  );
  script_osvdb_id(
    90830,
    91026,
    91027,
    91028,
    91029,
    91030,
    91031,
    91032,
    91033,
    91034,
    91037,
    91038
  );

  script_name(english:"HP Intelligent Management Center < 5.2 E401 Multiple Vulnerabilities");
  script_summary(english:"Checks version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The version of HP Intelligent Management Center running on the remote
host is affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of HP Intelligent Management Center running on the remote
host is potentially affected by multiple vulnerabilities :

  - A cross-site scripting vulnerability exists in the
    'opentopo_symbolid' parameter of the 'topoContent.jsf'
    script. (CVE-2012-5200)

  - Multiple code execution vulnerabilities exist.
    (CVE-2012-5201, CVE-2012-5209)

  - Multiple information disclosure vulnerabilities exist.
    (CVE-2012-5202, CVE-2012-5203, CVE-2012-5204,
     CVE-2012-5205, CVE-2012-5206, CVE-2012-5207,
     CVE-2012-5208, CVE-2012-5212, CVE-2012-5213)"
  );

  # https://h20566.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c03689276-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?43e66f46");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/525928/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2013/Mar/44");
  script_set_attribute(attribute:"see_also", value:"http://security.inshell.net/advisory/32");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-050");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-051");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-052");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-053");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-054");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-057");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-060");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-061");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-062");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-063");
  script_set_attribute(attribute:"solution", value:"Upgrade to 5.2 E401 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'HP Intelligent Management Center Arbitrary File Upload');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/13");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:intelligent_management_center");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies('hp_imc_detect.nbin');
  script_require_ports('Services/activemq', 61616);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Figure out which port to use
port = get_service(svc:'activemq', default:61616, exit_on_fail:TRUE);

version = get_kb_item_or_exit('hp/hp_imc/'+port+'/version');

# Versions 5.1 E0202 and earlier are affected
if (version =~ '^([0-4]\\.|5\\.(0\\-|1\\-E0([0-9]{1,2}|[01][0-9]{2}|20[02])([^0-9]|$)))')
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 5.2-E0401' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, 'HP Intelligent Management Center', port, version);
