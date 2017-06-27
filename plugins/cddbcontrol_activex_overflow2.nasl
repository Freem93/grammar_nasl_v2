#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25083);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2007-0443");
  script_bugtraq_id(23567);
  script_xref(name:"OSVDB", value:"34327");

  script_name(english:"Gracenote CDDBControl ActiveX Proxy Configuration Parameters Multiple Overflows");
  script_summary(english:"Checks for the CDDBControl ActiveX control"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is susceptible
to a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The Windows remote host contains the Gracenote CDDBControl ActiveX
control, which is used by various products, including AOL's software,
to lookup CD information in the Gracenote CDDB and is commonly marked
as safe for scripting. 

The version of this ActiveX control on the remote host reportedly
contains a buffer overflow vulnerability that arises when a large
string is supplied as an option for the control.  A remote attacker
may be able to leverage this issue to execute arbitrary code on the
remote host subject to the privileges of the current user." );
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-07-021.html" );
 script_set_attribute(attribute:"solution", value:
"Contact the developer of the software you are using for a patch or
new version; otherwise, use Gracenote's tool to set its kill bit
to disable the control in Internet Explorer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/04/23");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/04/19");
 script_cvs_date("$Date: 2017/05/08 18:22:10 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");

  script_dependencies("cddbcontrol_activex_overflow.nasl");
  script_require_keys("GraceNote/CDDBControl/Version");
  script_require_ports(139, 445);

  exit(0);
}

include ("global_settings.inc");
include("smb_func.inc");


version = get_kb_item("GraceNote/CDDBControl/Version");
if (!version) exit(0);

file = get_kb_item("GraceNote/CDDBControl/File");
flags = get_kb_item("GraceNote/CDDBControl/Flags");

ver = split(version, sep:".", keep:FALSE);
if (ver[0] == 2 &&
      (
        # 2.0-3 are affected
        (ver[1] <4) ||
        # 2.4.0.[0-13] are affected.
        (ver[1] == 4 && ver[2] == 0 && (ver[3] >= 0 && ver[3] <= 13)) ||
        # 2.5.0.[1-4] are affected.
        (ver[1] == 5 && ver[2] == 0 && (ver[3] >= 1 && ver[3] <= 4))
      )
    )
{
  # There's a problem if the kill bit isn't set.
  report = NULL;
    
  if (isnull(flags) || flags != 0x400) 
      report = string(
        "\n",
        "Version ", version, " of the control is installed as \n",
        "\n",
        "  ", file, "\n"
      );
   # Or we're just being paranoid.
   else if (report_paranoia > 1)
      report = string(
        "\n",
        "Version ", version, " of the control is installed as \n",
        "\n",
        "  ", file, "\n",
        "\n",
        "Note that the control may have its kill bit set, but the issue\n",
        "is being flagged because of the setting of Report Paranoia in\n",
        "effect when the scan was run.\n"
      );

   if (report) security_hole(port:kb_smb_transport(), extra:report);
}
