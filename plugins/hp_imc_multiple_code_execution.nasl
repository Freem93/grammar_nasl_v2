#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("xmlparse")) exit(1, "xmlparse() is not defined.");   # nb: used in the dependency.

include("compat.inc");


if(description)
{
  script_id(54999);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/02/07 18:43:41 $");

  script_cve_id(
    "CVE-2011-1848",
    "CVE-2011-1849",
    "CVE-2011-1850",
    "CVE-2011-1851",
    "CVE-2011-1852",
    "CVE-2011-1853",
    "CVE-2011-1854"
  );
  script_bugtraq_id(47789);
  script_osvdb_id(72391, 72392, 72393, 72394, 72395, 72396, 72397);
  
  script_name(english:"HP Intelligent Management Center Multiple Vulnerabilities");
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
host contains a number of vulnerabilities that can be exploited
remotely without authentication, including code execution and
arbitrary file creation."
  );

  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-160/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-161/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-162/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-163/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-164/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-165/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-166/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2011/May/83");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2011/May/84");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2011/May/85");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2011/May/87");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2011/May/88");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2011/May/99");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2011/May/101");
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02822750
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cd59d8c8");
  script_set_attribute(attribute:"solution", value:"Upgrade to 5.0_E0101L02 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/08");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:intelligent_management_center");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");
  script_family(english:"Gain a shell remotely");

  script_dependencies('hp_imc_detect.nbin');
  script_require_ports('Services/activemq');
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

# Figure out which port to use
port = get_service(svc:'activemq', exit_on_fail:TRUE);

version = get_kb_item_or_exit('hp/hp_imc/'+port+'/version');

# The advisory has two very specific versions
if (version == "5.0-E0101L01" || version == "5.0-E0101")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : 5.0-E0101L02' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "The HP Intelligent Management Center " + version + " install listening on port " + port + " is not affected.");

