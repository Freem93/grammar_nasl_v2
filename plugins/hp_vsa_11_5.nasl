#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76913);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/01/14 18:50:49 $");

  script_cve_id("CVE-2014-2605", "CVE-2014-2606");
  script_bugtraq_id(68538, 68542);
  script_osvdb_id(109166, 109167);
  script_xref(name:"HP", value:"emr_na-c04281279");
  script_xref(name:"HP", value:"HPSBST03039");
  script_xref(name:"HP", value:"SSRT101457");

  script_name(english:"HP StoreVirtual 4000 and StoreVirtual VSA Software < 11.5 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of HP StoreVirtual 4000 and StoreVirtual VSA Software (formerly known as LeftHand OS).");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote HP storage system, running HP StoreVirtual 4000 Storage and
StoreVirtual VSA, is version 9.5.x or later but prior to 11.5. It is,
therefore, affected by the following vulnerabilities :

  - An unspecified information disclosure vulnerability
    exists that allows a remote attacker to obtain
    potentially sensitive information via unknown vectors.
    (CVE-2014-2605)

  - A privilege escalation vulnerability exists that allows
    an authenticated, remote attacker to gain privileges via
    unknown vectors. (CVE-2014-2606)");
  # http://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c04281279
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fa6545a2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP StoreVirtual 4000 Storage and StoreVirtual VSA version
11.5 or higher.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:storevirtual_vsa");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:storage_management_software");
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
if (versions)
{
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

    fix = '11.5';
    lower_bound = '9.5';
    if (
      ver_compare(ver:ver, fix:fix, strict:FALSE) < 0 &&
      ver_compare(ver:ver, fix:lower_bound, strict:FALSE) >= 0
    )
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
}

if (!vuln) audit(AUDIT_HOST_NOT, 'affected');
