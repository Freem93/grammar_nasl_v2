#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(66555);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/05/24 10:53:15 $");

  script_cve_id("CVE-2013-0138");
  script_bugtraq_id(59309);
  script_osvdb_id(92630);
  script_xref(name:"CERT", value:"880916");

  script_name(english:"BitZipper 2013 < 2013 Update 1 Memory Corruption Vulnerability");
  script_summary(english:"Checks version of BitZipper");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host has a data compression tool that is affected 
by a memory corruption vulnerability.");
  script_set_attribute( attribute:"description", value:
"The version of BitZipper is 2013 prior to update 1 (2013.13.4.16). As 
such, it is affected by a memory corruption vulnerability triggered
when handling a crafted ZIP file.    

An attacker could exploit this issue by tricking a user into opening a
specially crafted ZIP file, resulting in arbitrary code execution.");

  script_set_attribute(attribute:"solution", value:
"Upgrade to BitZipper 2013 Update 1 (2013.13.4.16) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false"); 
  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/23");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bitberry_software:bitzipper");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("bitzipper_installed.nasl");
  script_require_keys("SMB/bitberry_bitzipper/Installed");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

appname = "BitZipper";
kb_base = "SMB/bitberry_bitzipper/";

path = get_kb_item_or_exit(kb_base + "Path");
version = get_kb_item_or_exit(kb_base + "Version");
ver = split(version, sep:'.', keep:FALSE);
port = kb_smb_transport();
if(!port) port = 445;

if(ver[0] == 2013 && 
  (
    ver[1] < 13 || 
    (  
      ver[1] == 13 && 
      (
        ver[2] < 4 || (ver[2] == 4 && ver[3] < 16)
      )
    )
  )
)
{
  if (report_verbosity > 0)
  {
    report =
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed             : 2013.13.4.16 (2013 Update 1)\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);
