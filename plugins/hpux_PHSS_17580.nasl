#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(17445);
 script_version ("$Revision: 1.5 $");

 name["english"] = "HP-UX Security patch : PHSS_17580";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing HP-UX Security Patch number PHSS_17580 .
(Security Vulnerability in MC/ServiceGuard & MC/LockManager)" );
 script_set_attribute(attribute:"solution", value:
"ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s800/10.X/PHSS_17580" );
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_set_attribute(attribute:"see_also", value:"HPUX security bulletin 096" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/18");
  script_cvs_date("$Date: 2016/11/18 20:51:40 $");
 script_end_attributes();

 
 summary["english"] = "Checks for patch PHSS_17580";
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

if ( ! hpux_check_ctx ( ctx:"800:10.20 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHSS_17580 PHSS_18321 PHSS_19473 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"Cluster-Monitor.CM-CORE", version:NULL) )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Cluster-Mon-Jpn.J-CM-CORE", version:NULL) )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Package-Manager.CM-PKG", version:NULL) )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"Package-Mgr-Jpn.J-CM-PKG", version:NULL) )
{
 security_hole(0);
 exit(0);
}
