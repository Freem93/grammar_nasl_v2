#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(42180);
 script_version ("$Revision: 1.8 $");

 script_bugtraq_id(36720);

 script_name(english:"Intel Desktop Boards BIOS Unauthorized BIOS Flash (INTEL-SA-00019)");
 script_summary(english:"Check the Intel BIOS version.");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to flash the BIOS on the remote desktop system without
explicit authorization.");
 script_set_attribute(attribute:"description", value:
"The version of the Intel BIOS on the remote host allows an
unauthorized user to flash the BIOS without explicit authorization
from a user or supervisor. An attacker can exploit this vulnerability
to flash the BIOS and downgrade it to an older version, which allows
the attacker to gain unauthorized access to system.");
 script_set_attribute(attribute:"see_also", value:"http://invisiblethingslab.com/press/itl-press-2009-03.pdf");
 # https://security-center.intel.com/advisory.aspx?intelid=INTEL-SA-00019&languageid=en-fr
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f0197bd");
 script_set_attribute(attribute:"solution",  value:
"Upgrade the system BIOS on the remote host.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 
 script_set_attribute(attribute:"vuln_publication_date", value:"2009/10/16");
 script_set_attribute(attribute:"patch_publication_date", value:"2009/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/19");
 
 script_cvs_date("$Date: 2014/11/26 11:46:02 $");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english: "Misc.");
 
 script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");

 script_dependencies("bios_get_info_ssh.nasl", "bios_get_info_smb_reg.nasl");
 script_require_keys("BIOS/Version", "BIOS/Vendor");
 exit(0);
}

version = get_kb_item("BIOS/Version");
if (! version) exit(1,"The 'BIOS/Version' KB is missing.");

vendor = get_kb_item("BIOS/Vendor");
if (vendor !~ "^Intel ") exit(0,"The remote BIOS is not from Intel.");

updates = make_list(
"MJG4110H.86A.0004",
"RQG4110H.86A.0011",
"APQ4310H.86A.0025",
"TYG4110H.86A.0030",
"LDB4310H.86A.0031",
"JT94510H.86A.0032",
"CBQ4510H.86A.0087",
"NBG4310H.86A.0087",
"IDG4510H.86A.0105",
"ECG3510M.86A.0117.2009.0625.1315",
"SGP4510H.86A.0118",
"LF94510J.86A.0183",
"DPP3510J.86A.0572",
"JOQ3510J.86A.1108",
"XS54010J.86A.1338",
"BTX3810J.86A.2000",
"SOX5810J.86A.4196");

v = split(version, sep: '.', keep:FALSE);
if (max_index(v) < 3) exit(1,"max_index (v) < 3");
if(isnull(v[1]) || v[1] != "86A") exit(0, "Null v[1] or v[1] ne 86A");

report = NULL;
foreach u (updates)
{
 w = split(u, sep: '.', keep:FALSE);
 
 if(v[0] == 'ECG3510M')
 {
  if (int(v[2]) < int(w[2]) ||
       v[2] == w[2] && ( int(v[3]) < int(w[3]) ||
            v[3] == w[3] && int(v[4]) < int(w[4]) || 
                 v[4] == w[4] && int(v[5]) < int(w[5]))
     )
  report = string("\n","Update to '",u,"'.\n"); 
 } 
 else if((v[0] == w[0]) && (int(v[2]) < int(w[2])))
   report = string("\n","Update to '",u,"'.\n"); 
 
 if(!isnull(report))
 {  
   security_warning(port: 0, extra:report);
   exit(0);
 } 
}
exit(0, "Installed Intel BIOS version '" + version + "' is not affected.");
