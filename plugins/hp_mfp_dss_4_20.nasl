#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(56651);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/06/21 21:44:54 $");

  script_cve_id("CVE-2011-3163");
  script_bugtraq_id(50297);
  script_osvdb_id(76678);

  script_name(english:"HP MFP Digital Sending Software 4.9x <= 4.91.21 Local Workflow Metadata Information Disclosure");
  script_summary(english:"Checks the version of hpbs2e.exe");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Windows host contains an application affected by a local
information disclosure vulnerability."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote Windows host contains a version of HP MFP Digital Sending
Software version 4.9x that's 4.91.21 or earlier.  It is reportedly 
affected by a local information disclosure vulnerability that could 
result in disclosure of personal information in workflow metadata."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/archive/1/520162/30/0/threaded"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Install HP MFP Digital Sending Software version 4.20.

Note that, while 4.9x represents a re-architecture of HP MFP Digital
Signing Software 4.20 to enable support for FutureSmart devices, the
only fix HP currently provides is to move to 4.20 from the 4.9x
release branch."
  );
 script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:multifunction_peripheral_digital_sending_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");

  script_dependencies("hp_mfp_dss_installed.nasl");
  script_require_keys("SMB/HP_MFP_DSS/Version");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/HP_MFP_DSS/Version");

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# nb: HP's advisory says "v4.91.21 and all previous 4.9x versions" are affected.
#     also, 4.9x is a different branch that exists alongside 4.20 and earlier. 
if (
  ver[0] == 4 &&
  (
    ver[1] == 90 ||
    (ver[1] == 91 && ver[2] <= 21)
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
      '\n  Fixed version     : 4.20\n';
    security_note(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_note(get_kb_item("SMB/transport"));
}
else exit(0, "The host is not affected since HP MFP Digital Sending Software "+version+" is installed.");
