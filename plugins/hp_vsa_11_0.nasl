#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73463);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/01/14 18:50:49 $");

  script_cve_id("CVE-2013-4841");
  script_bugtraq_id(65770);
  script_osvdb_id(103715);
  script_xref(name:"HP", value:"HPSBST02937");
  script_xref(name:"HP", value:"SSRT100796");
  script_xref(name:"HP", value:"emr_na-c03995204");
  script_xref(name:"ZDI", value:"ZDI-14-051");

  script_name(english:"HP StoreVirtual 4000 and StoreVirtual VSA Software dbd_manager RCE");
  script_summary(english:"Checks the version of LeftHand OS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote HP storage system running LeftHand OS is affected by an
unspecified remote arbitrary code execution vulnerability in the
dbd_manager component.");
  # http://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c03995204
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5ea42332");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-051/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to LeftHand OS version 11.0 or higher.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:lefthand");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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

  fix = '11.0';
  if (ver_compare(ver:ver, fix:fix, strict:FALSE) < 0)
  {
    vuln = TRUE;

    if (report_verbosity > 0)
    {
      report =
        '\n  Installed version : ' + ver +
        '\n  Fixed version     : ' + fix + '\n';
      if (udp) security_hole(port:port, extra:report, proto:'udp');
      else security_hole(port:port, extra:report);
    }
    else
    {
      if (udp) security_hole(port:port, proto:'udp');
      else security_hole(port);
    }
  }
}

if (!vuln) audit(AUDIT_HOST_NOT, 'affected');
