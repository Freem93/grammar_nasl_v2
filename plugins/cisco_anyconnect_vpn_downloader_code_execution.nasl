#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59820);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/10/05 20:44:33 $");

  script_cve_id("CVE-2012-2493");
  script_bugtraq_id(54107);
  script_osvdb_id(83096);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtw47523");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20120620-ac");
  script_xref(name:"ZDI", value:"ZDI-12-156");

  script_name(english:"Cisco AnyConnect Secure Mobility Client VPN Downloader RCE (cisco-sa-20120620-ac)");
  script_summary(english:"Checks version of Cisco AnyConnect Client");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has software installed that is affected by an
arbitrary code execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has a version of Cisco AnyConnect < 2.5 MR6.
Such versions are potentially affected by an arbitrary code execution
vulnerability.  The WebLaunch VPN downloader implementation does not 
properly validate binaries that are received, which can allow remote 
attackers to execute arbitrary code via ActiveX or Java components."
  );
  # # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20120620-ac
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b0b6c065");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-156/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Aug/278");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Cisco AnyConnect Secure Mobility Client 2.5 MR6 or greater."
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
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies('cisco_anyconnect_vpn_installed.nasl');
  script_require_keys('SMB/cisco_anyconnect/Installed');
  
  exit(0);
}

include('global_settings.inc');
include('misc_func.inc');

appname = 'Cisco AnyConnect Mobility VPN Client';
kb_base = 'SMB/cisco_anyconnect/';
report = '';

num_installed = get_kb_item_or_exit(kb_base + 'NumInstalled');

for (install_num = 0; install_num < num_installed; install_num++)
{
  path = get_kb_item_or_exit(kb_base + install_num + '/path');
  ver = get_kb_item_or_exit(kb_base + install_num + '/version');
  fix = '2.5.6005.0';
  
  if (ver =~ "^2\." && ver_compare(ver:ver, fix:fix) == -1) 
  {
      report += 
        '\n  Path              : ' + path +
        '\n  Installed version : ' + ver +
        '\n  Fixed version     : ' + fix + '\n';
  }
}

if(report != '')
{
  if (report_verbosity > 0)
    security_hole(port:get_kb_item('SMB/transport'), extra:report);
  else security_hole(get_kb_item('SMB/transport'));
  exit(0);
} 
else exit(0, 'No affected ' +  appname + ' installs found.');
