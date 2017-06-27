#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25655);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2007-3554");
  script_bugtraq_id(24730);
  script_osvdb_id(37832);
  script_xref(name:"EDB-ID", value:"4137");
  
  script_name(english:"HP Instant Support Driver Check HPSDDX Class (SDD) ActiveX (sdd.dll) queryHub Function Overflow");
  script_summary(english:"Checks versions of SDD ActiveX control"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by a
buffer overflow issue." );
 script_set_attribute(attribute:"description", value:
"The remote host contains the SDD ActiveX control, a part of HP Instant
Support. 

The version of this control on the remote host is reportedly affected
by a buffer overflow that can be triggered by a long argument to its
'queryHub' method.  If an attacker can trick a user on the affected
host into visiting a specially crafted web page, these issues could
be leveraged to execute arbitrary code on the host subject to the 
user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2007/Jul/16" );
 # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01077597
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?42a01f91" );
 script_set_attribute(attribute:"solution", value:
"Either disable the use of this ActiveX control from within Internet
Explorer by setting its kill bit or upgrade it to version 1.5.0.3 or
later following the vendor advisory referenced above." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/07/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/07/04");
 script_set_attribute(attribute:"patch_publication_date", value: "2007/06/13");
 script_cvs_date("$Date: 2016/10/27 15:03:53 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:instant_support");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("smb_func.inc");
include("smb_activex_func.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Locate files used by the controls.
if (activex_init() != ACX_OK) exit(0);

clsid = "{156BF4B7-AE3A-4365-BD88-95A75AF8F09D}";
file = activex_get_filename(clsid:clsid);
if (file)
{
  ver = activex_get_fileversion(clsid:clsid);
  if (ver && activex_check_fileversion(clsid:clsid, fix:"1.5.0.3") == TRUE)
  {
    report = NULL;
    if (report_paranoia > 1)
      report = string(
        "According to the registry, version '", ver, "' of the vulnerable\n",
        "control is installed as :\n",
        "\n",
        "  ", file, "\n",
        "\n",
        "Note, though, that Nessus did not check whether the kill bit was\n",
        "set for the control's CLSID because of the Report Paranoia setting\n",
        "in effect when this scan was run.\n"
      );
    else if (activex_get_killbit(clsid:clsid) == 0)
      report = string(
        "According to the registry, version '", ver, "' of the vulnerable\n",
        "control is installed as :\n",
        "\n",
        "  ", file, "\n",
        "\n",
        "Moreover, its kill bit is not set so it is accessible via\n",
        "Internet Explorer."
      );
    if (report) security_hole(port:kb_smb_transport(), extra:report);
  }
}
activex_end();
