#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(17044);
 script_version ("$Revision: 1.5 $");

 name["english"] = "HP-UX Security patch : PHSS_9690";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing HP-UX Security Patch number PHSS_9690 .
(Security vulnerability bypassing proper authentication)" );
 script_set_attribute(attribute:"solution", value:
"ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/10.X/PHSS_9690" );
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_set_attribute(attribute:"see_also", value:"HPUX security bulletin 046" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/16");
  script_cvs_date("$Date: 2016/11/18 20:51:41 $");
 script_end_attributes();

 
 summary["english"] = "Checks for patch PHSS_9690";
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

if ( ! hpux_check_ctx ( ctx:"800:10.10 700:10.10 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHSS_9690 PHSS_9802 PHSS_11172 PHSS_12137 PHSS_13402 PHSS_13723 PHSS_14594 PHSS_16150 PHSS_23355 PHSS_25136 PHSS_25548 PHSS_25785 PHSS_26488 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"CDE.CDE-RUN", version:NULL) )
{
 security_hole(0);
 exit(0);
}
