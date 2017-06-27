#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52614);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/21 22:04:45 $");

  script_cve_id("CVE-2011-0279");
  script_bugtraq_id(46679);
  script_osvdb_id(75048);
  script_xref(name:"Secunia", value:"43618");

  script_name(english:"HP MFP Digital Sending Software 4.91.0 Local Authentication Bypass");
  script_summary(english:"Checks the version obtained by hp_mfp_dss_installed.nasl");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
an authentication bypass vulnerability.");

  script_set_attribute(attribute:"description", value:
"The remote Windows host contains HP MFP Digital Sending Software
version 4.91.0.  This version is potentially affected by an
authentication bypass vulnerability related to device configuration
templates. 

A local attacker, exploiting this flaw, reportedly can gain
unauthorized access to functionality of an HP Multifunction Peripheral
(MFP) that is controlled by the HP MFP Digital Sending Software. 

Note: the provided solution is needed only if authentication is
required and the previous device configuration template did not
include authentication settings.");
  # https://h20564.www2.hp.com/hpsc/doc/public/display?docId=emr_na-c02738104
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f019df14");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2011/Mar/57");
  script_set_attribute(attribute:"solution", value:
"At the time of this writing, a patch has not been provided by the
vendor.  However, a workaround has been provided by the vendor:

  - Require authentication for all device templates.

  - For all devices previously configured via device
    templates, reconfigure the devices with these revised
    templates.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/02");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:multifunction_peripheral_digital_sending_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("hp_mfp_dss_installed.nasl");
  script_require_keys("SMB/HP_MFP_DSS/Version");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/HP_MFP_DSS/Version");

if (version =~ "^4\.91($|(\.0+)+$)")
{
  if (report_verbosity > 0)
  {
    path = get_kb_item('SMB/HP_MFP_DSS/Path');
    if (isnull(path)) path = 'n/a';

    report = 
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version;  
    security_note(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_note(get_kb_item("SMB/transport"));
}
else exit(0, "The host is not affected since HP MFP Digital Sending Software "+version+" is installed.");
