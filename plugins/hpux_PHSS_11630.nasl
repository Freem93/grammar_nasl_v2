#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(17435);
 script_version ("$Revision: 1.5 $");

 name["english"] = "HP-UX Security patch : PHSS_11630";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing HP-UX Security Patch number PHSS_11630 .
(Buffer overflows in X11/Motif libraries)" );
 script_set_attribute(attribute:"solution", value:
"ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/10.X/PHSS_11630" );
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_set_attribute(attribute:"see_also", value:"HPUX security bulletin 067" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/18");
  script_cvs_date("$Date: 2016/11/18 20:51:39 $");
 script_end_attributes();

 
 summary["english"] = "Checks for patch PHSS_11630";
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

if ( hpux_patch_installed (patches:"PHSS_11630 PHSS_12376 PHSS_14082 PHSS_15010 PHSS_16121 PHSS_16619 PHSS_17325 PHSS_19962 PHSS_21043 PHSS_21958 PHSS_22945 PHSS_23519 PHSS_28365 PHSS_28873 PHSS_29127 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"X11MotifDevKit.X11R6-PRG", version:NULL) )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"X11MotifDevKit.MOTIF12-PRG", version:NULL) )
{
 security_hole(0);
 exit(0);
}
