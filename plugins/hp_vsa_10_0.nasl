#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64633);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/01/14 18:50:49 $");

  script_cve_id(
    "CVE-2012-3282",
    "CVE-2012-3283",
    "CVE-2012-3284",
    "CVE-2012-3285",
    "CVE-2013-2343"
  );
  script_bugtraq_id(57754, 60884);
  script_osvdb_id(89917, 89918, 89919, 89920, 94701);
  script_xref(name:"EDB-ID", value:"27555");
  script_xref(name:"HP", value:"HPSBST02846");
  script_xref(name:"HP", value:"SSRT100798");
  script_xref(name:"HP", value:"emr_na-c03661318");
  script_xref(name:"ZDI", value:"ZDI-13-014");
  script_xref(name:"ZDI", value:"ZDI-13-015");
  script_xref(name:"ZDI", value:"ZDI-13-016");
  script_xref(name:"ZDI", value:"ZDI-13-017");
  script_xref(name:"ZDI", value:"ZDI-13-179");

  script_name(english:"HP LeftHand Virtual SAN Appliance < 10.0 hydra Service Multiple RCE");
  script_summary(english:"Checks the VSA version.");

  script_set_attribute(attribute:"synopsis", value:
"A management service on the remote host has multiple remote code
execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to the version fingerprinted by Nessus, the remote host is
an HP LeftHand Virtual SAN Appliance prior to version 10.0. It is,
therefore, affected by multiple unspecified remote code execution
vulnerabilities in the hydra service.");
  #script_set_attribute(attribute:"see_also", value:"http://zerodayinitiative.com/advisories/ZDI-12-166/"); # there has been no confirmation from ZDI or HP that this was fixed in 10.0
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-014/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-015/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-016/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-017/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-179/");
  # http://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c03661318
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8079ef31");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/527020/30/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP LeftHand Virtual SAN Appliance version 10.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'HP StorageWorks P4000 Virtual SAN Appliance Login Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:san/iq");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("hp_saniq_hydra_detect.nbin", "hp_lefthand_console_discovery.nasl", "hp_lefthand_hydra_detect.nasl");
  script_require_ports("Services/saniq_hydra", "Services/hydra_13841", "Services/saniq_console_discovery", "Services/udp/saniq_console_discovery");

  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");

vuln = FALSE;

# next, explicitly check any version numbers that were obtained via console discovery or hydra
versions = get_kb_list_or_exit('lefthand_os/*/version');
foreach key (keys(versions))
{
  port = key - 'lefthand_os/' - '/version';
  if ('udp' >< port)
  {
    port = port - 'udp/';
    udp = TRUE;
  }
  else udp = FALSE;

  ver = versions[key];
  if (isnull(ver)) continue;

  fix = '10.0';
  if (ver_compare(ver:ver, fix:fix, strict:FALSE) < 0)
  {
    vuln = TRUE;

    if (report_verbosity > 0)
    {
      report =
        '\n  Installed version : ' + ver +
        '\n  Fixed version : ' + fix + '\n';
      if (udp)
        security_hole(port:port, extra:report, proto:'udp');
      else
        security_hole(port:port, extra:report);
    }
    else
    {
      if (udp)
        security_hole(port:port, proto:'udp');
      else
        security_hole(port);
    }
  }
}

if (!vuln)
  audit(AUDIT_HOST_NOT, 'affected');
