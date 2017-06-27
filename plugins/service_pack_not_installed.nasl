#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(26921);
 script_version("$Revision: 1.33 $");
 script_cvs_date("$Date: 2017/01/10 18:05:24 $");

 script_cve_id(
  "CVE-1999-0662",
  "CVE-2003-0350",
  "CVE-2003-0507",
  "CVE-2007-1537"
 );
 script_bugtraq_id(
  7930,
  8090,
  8128,
  8154,
  10897,
  11202,
  12969,
  12972,
  13008,
  23025
 );
 script_osvdb_id(
  2237,
  12655,
  13410,
  33628
 );

 script_name(english:"Windows Service Pack Out-of-Date");
 script_summary(english:"Determines the remote SP.");

 script_set_attribute(attribute:"synopsis", value:
"The remote system is not up to date.");
 script_set_attribute(attribute:"description", value:
"The remote version of Microsoft Windows has no service pack or the one
installed is no longer supported. As a result, it is likely to contain
security vulnerabilities.");
 script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/lifecycle");
 script_set_attribute(attribute:"solution", value:
"Install the latest service pack.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/07/02");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/05");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");

 script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");

 script_dependencies(
   "smb_reg_service_pack.nasl", "smb_reg_service_pack_W2K.nasl",
   "smb_reg_service_pack_XP.nasl", "smb_reg_service_pack_W2003.nasl",
   "smb_reg_service_pack_vista.nasl", "smb_reg_service_pack_win7.nasl",
   "smb_reg_service_pack_win8.nasl", "smb_reg_service_pack_win8_1.nasl"
 );
 script_exclude_keys("SMB/not_windows");
 script_require_keys("SMB/WindowsVersion");

 exit(0);
}

include("audit.inc");

if (get_kb_item("SMB/not_windows")) audit(AUDIT_OS_NOT, "Windows");


win_sp["4.0"] = "6a";
win_sp["5.0"] = "4";
win_sp["5.1"] = "3";
win_sp["5.2"] = "2";
win_sp["6.0"] = "2";
win_sp["6.1"] = "1";
win_sp["6.2"] = "0";
win_sp["6.3"] = "0";

win_min_sp["4.0"] = "6a";
win_min_sp["5.0"] = "4";
win_min_sp["5.1"] = "3";
win_min_sp["5.2"] = "2";
win_min_sp["6.0"] = "2";
win_min_sp["6.1"] = "1";
win_min_sp["6.2"] = "0";
win_min_sp["6.3"] = "0";

report = NULL;

win = get_kb_item("SMB/WindowsVersion");
if (win)
{
 port = get_kb_item("SMB/transport");
 if(!port)port = 445;

 sp = get_kb_item("SMB/CSDVersion");

 if (!sp)
   sp = "Service Pack 0";

 vers = ereg_replace(pattern:"^.*(Service Pack|Szervizcsomag) (.*)$", string:sp, replace:"\2");
 if (int(vers) < int(win_min_sp[win]))
   report = sp;

 if (report)
 {
  report = string ("\n",
		"The remote Windows ", win, " system has ", report , " applied.\n",
		"The system should have Service Pack ", win_sp[win], " installed.");

  security_hole(extra:report, port:port);
 } else exit(0, "The remote Windows install has the recommended service pack installed.");
} else exit(0, "The 'SMB/WindowsVersion' KB item is missing.");
