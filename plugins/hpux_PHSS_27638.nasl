#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(16782);
 script_version ("$Revision: 1.5 $");

 name["english"] = "HP-UX Security patch : PHSS_27638";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing HP-UX Security Patch number PHSS_27638 .
(SSRT2332 rev.10 Apache Server Chunk Encoding)" );
 script_set_attribute(attribute:"solution", value:
"ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/10.X/PHSS_27638" );
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_set_attribute(attribute:"see_also", value:"HPUX security bulletin 197" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/16");
  script_cvs_date("$Date: 2016/11/18 20:51:40 $");
 script_end_attributes();

 
 summary["english"] = "Checks for patch PHSS_27638";
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

if ( hpux_patch_installed (patches:"PHSS_27638 PHSS_27746 PHSS_27835 PHSS_27916 PHSS_28091 PHSS_28094 PHSS_28257 PHSS_28347 PHSS_28399 PHSS_28472 PHSS_28545 PHSS_28586 PHSS_28704 PHSS_28877 PHSS_29205 PHSS_29428 PHSS_29753 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"OVPlatform.OVWWW-SRV", version:"	OVPlatform.OVWWW-SRV,B.06.20.00") )
{
 security_hole(0);
 exit(0);
}
