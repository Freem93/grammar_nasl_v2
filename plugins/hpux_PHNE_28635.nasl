#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(17416);
 script_version ("$Revision: 1.6 $");

 name["english"] = "HP-UX Security patch : PHNE_28635";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing HP-UX Security Patch number PHNE_28635 .
(SSRT3451 Potential Security Vulnerability in HP-UX network drivers (Data Leakage) (rev. 01))" );
 script_set_attribute(attribute:"solution", value:
"ftp://ftp.itrc.hp.com/hp-ux_patches/s700_800/10.X/PHNE_28635" );
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_set_attribute(attribute:"see_also", value:"HPUX security bulletin 261" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/18");
  script_cvs_date("$Date: 2016/11/18 20:51:39 $");
 script_end_attributes();

 
 summary["english"] = "Checks for patch PHNE_28635";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 family["english"] = "HP-UX Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/HP-UX/swlist");
 exit(0);
}

include("hpux.inc");

if ( ! hpux_check_ctx ( ctx:"800:10.20 700:10.20 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHNE_28635 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"100BT-EISA-KRN.100BT-KRN", version:"	100BT-EISA-KRN.100BT-KRN,B.10.20.01,B.10.20.02,B.10.20.03") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"100BT-EISA-KRN.100BT-KRN", version:"	100BT-EISA-KRN.100BT-KRN,B.10.20.04,B.10.20.05") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"100BT-EISA-RUN.100BT-INIT", version:"	100BT-EISA-RUN.100BT-INIT,B.10.20.01,B.10.20.02,B.10.20.03") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"100BT-EISA-RUN.100BT-INIT", version:"	100BT-EISA-RUN.100BT-INIT,B.10.20.04,B.10.20.05") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"100BT-EISA-RUN.100BT-RUN", version:"	100BT-EISA-RUN.100BT-RUN,B.10.20.01,B.10.20.02,B.10.20.03") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"100BT-EISA-RUN.100BT-RUN", version:"	100BT-EISA-RUN.100BT-RUN,B.10.20.04,B.10.20.05") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"100BT-EISA-FMT.100BT-FORMAT", version:"	100BT-EISA-FMT.100BT-FORMAT,B.10.20.01,B.10.20.02,B.10.20.03") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"100BT-EISA-FMT.100BT-FORMAT", version:"	100BT-EISA-FMT.100BT-FORMAT,B.10.20.04,B.10.20.05") )
{
 security_hole(0);
 exit(0);
}
