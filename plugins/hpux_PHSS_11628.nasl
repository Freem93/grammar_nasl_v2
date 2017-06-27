#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(17031);
 script_version ("$Revision: 1.6 $");

 name["english"] = "HP-UX Security patch : PHSS_11628";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing HP-UX Security Patch number PHSS_11628 .
(Buffer overflows in X11/Motif libraries)" );
 script_set_attribute(attribute:"solution", value:
"ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/10.X/PHSS_11628" );
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_set_attribute(attribute:"see_also", value:"HPUX security bulletin 067" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/16");
  script_cvs_date("$Date: 2016/11/18 20:51:39 $");
 script_end_attributes();

 
 summary["english"] = "Checks for patch PHSS_11628";
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

if ( hpux_patch_installed (patches:"PHSS_11628 PHSS_12374 PHSS_12824 PHSS_13113 PHSS_13743 PHSS_14040 PHSS_14534 PHSS_15008 PHSS_16120 PHSS_16617 PHSS_17331 PHSS_17323 PHSS_18012 PHSS_19592 PHSS_19963 PHSS_20861 PHSS_21956 PHSS_22944 PHSS_23518 PHSS_25446 PHSS_27229 PHSS_28364 PHSS_28872 PHSS_29126 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"X11.X11R5-SHLIBS", version:NULL) )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"X11.X11R6-SHLIBS", version:NULL) )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"X11.MOTIF12-SHLIB", version:NULL) )
{
 security_hole(0);
 exit(0);
}
