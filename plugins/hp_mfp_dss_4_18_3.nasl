#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46676);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2013/06/21 21:42:44 $");

  script_cve_id("CVE-2010-1558");
  script_bugtraq_id(40147);
  script_osvdb_id(64661);

  script_name(english:"HP MFP Digital Sending Software < 4.18.3 Local Unspecified Authentication Bypass");
  script_summary(english:"Checks the version of HP MFP Digital Sending Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
an authentication bypass vulnerability.");

  script_set_attribute(attribute:"description", value:
"The remote Windows host contains a version of HP MFP Digital Sending
Software earlier than 4.18.3.  Such versions are potentially affected
by an unspecified authentication bypass vulnerability. 

A local attacker, exploiting this flaw, reportedly can gain
unauthorized access to 'Send to email' and other functionalities of an
HP Multifunction Peripheral (MFP) that is controlled by the HP Digital
Sending Software.");

  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/511283/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/511825/30/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP MFP Digital Sending Software 4.18.5 or later. 

Note that HP initially recommended upgrading to version 4.18.3.  While
that version does address the vulnerability, it also introduces a
non-security defect and HP now recommends upgrading to version 4.18.5.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/19");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:multifunction_peripheral_digital_sending_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");

  script_dependencies("hp_mfp_dss_installed.nasl");
  script_require_keys("SMB/HP_MFP_DSS/Version");

  exit(0);
}

include("global_settings.inc");

version = get_kb_item("SMB/HP_MFP_DSS/Version");
if (isnull(version)) exit(1, "The 'SMB/HP_MFP_DSS/Version' KB item is missing.");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 4 ||
  (
    ver[0] == 4 &&
    (
      ver[1] < 18 ||
      (ver[1] == 18 && ver[2] < 3)
    )
  )
)
{
  if (report_verbosity > 0)
  {
    path = get_kb_item('SMB/HP_MFP_DSS/Path');
    if (isnull(path)) path = 'n/a';

    report = 
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : 4.18.3\n';
    security_warning(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_warning(get_kb_item("SMB/transport"));
}
else exit(0, "The host is not affected since HP MFP Digital Sending Software "+version+" is installed.");
