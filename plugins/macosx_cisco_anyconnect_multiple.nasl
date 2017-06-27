#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59823);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/10/03 20:33:39 $");

  script_cve_id(
    "CVE-2012-2493",
    "CVE-2012-2494",
    "CVE-2012-2495"
  );
  script_bugtraq_id(54107, 54108);
  script_osvdb_id(83096, 83159);
  script_xref(name:"ZDI", value:"ZDI-12-149");
  script_xref(name:"ZDI", value:"ZDI-12-156");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20120620-ac");

  script_name(english:"MacOSX Cisco AnyConnect Secure Mobility Client Multiple Vulnerabilities");
  script_summary(english:"Checks version of Cisco AnyConnect Client");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has software installed that is affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has a version of Cisco AnyConnect < 2.5 MR6 / 3.0 MR8.
Such versions are potentially affected by multiple vulnerabilities :

  - The WebLaunch VPN downloader implementation does not 
    properly validate binaries that are received, which can 
    allow remote attackers to execute arbitrary code via 
    ActiveX of Java components. (CVE-2012-2493).

  - The WebLaunch VPN downloader implementation does not 
    compare timestamps of offered software to install with 
    currently installed software, which may allow remote 
    attackers to downgrade the software via ActiveX of Java 
    components. (CVE-2012-2494, CVE-2012-2495)."
  );
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20120620-ac
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b0b6c065");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-149/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-156/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Aug/269");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Aug/278");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Cisco AnyConnect Secure Mobility Client 2.5 MR6 / 3.0 MR8
or greater."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date",value:"2012/06/20");
  script_set_attribute(attribute:"patch_publication_date",value:"2012/06/20");
  script_set_attribute(attribute:"plugin_publication_date",value:"2012/07/02");
  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:cisco:anyconnect_secure_mobility_client");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
  
  script_dependencies("macosx_cisco_anyconnect_installed.nasl");
  script_require_keys("MacOSX/Cisco_AnyConnect/Installed");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");

appname = 'Cisco AnyConnect Mobility VPN Client';

kb_base = "MacOSX/Cisco_AnyConnect";
get_kb_item_or_exit(kb_base+"/Installed");
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);
version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);

fix2 = '2.5.6005.0';
fix3 = '3.0.8057.0';

if ((version =~ "^2\." && ver_compare(ver:version, fix:fix2, strict:FALSE) == -1) ||
    (version =~ "^3\." && ver_compare(ver:version, fix:fix3, strict:FALSE) == -1))
{
  if(version =~ "^2\.")
    fix = fix2;
  else
    fix = fix3;
  
  if (report_verbosity > 0)
  {
    report = 
      '\n  Path              : ' + path + 
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : ' + fix + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, appname, version);
