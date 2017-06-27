#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(17049);
 script_version ("$Revision: 1.5 $");

 name["english"] = "HP-UX Security patch : PHSS_9627";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing HP-UX Security Patch number PHSS_9627 .
(Security vulnerability bypassing proper authentication)" );
 script_set_attribute(attribute:"solution", value:
"ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/10.X/PHSS_9627" );
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_set_attribute(attribute:"see_also", value:"HPUX security bulletin 046" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/16");
  script_cvs_date("$Date: 2016/11/18 20:51:41 $");
 script_end_attributes();

 
 summary["english"] = "Checks for patch PHSS_9627";
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

if ( hpux_patch_installed (patches:"PHSS_9627 PHSS_9803 PHSS_11147 PHSS_12138 PHSS_12587 PHSS_13403 PHSS_13724 PHSS_14002 PHSS_14595 PHSS_16147 PHSS_16362 PHSS_15795 PHSS_16966 PHSS_17268 PHSS_17329 PHSS_17566 PHSS_18425 PHSS_19482 PHSS_19747 PHSS_20715 PHSS_20860 PHSS_22319 PHSS_22339 PHSS_23516 PHSS_23796 PHSS_23798 PHSS_25137 PHSS_25192 PHSS_25786 PHSS_26489 PHSS_27426 PHSS_27877 PHSS_29201 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"CDE.CDE-RUN", version:NULL) )
{
 security_hole(0);
 exit(0);
}
