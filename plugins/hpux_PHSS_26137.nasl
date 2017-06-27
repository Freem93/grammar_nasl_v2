#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(16572);
 script_version ("$Revision: 1.5 $");

 name["english"] = "HP-UX Security patch : PHSS_26137";
 
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote host is missing HP-UX Security Patch number PHSS_26137 .
(Sec. Vulnerability in SNMP (rev. 16))" );
 script_set_attribute(attribute:"solution", value:
"ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/10.X/PHSS_26137" );
 script_set_attribute(attribute:"risk_factor", value:"High");
 script_set_attribute(attribute:"see_also", value:"HPUX security bulletin 184" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/16");
  script_cvs_date("$Date: 2016/11/18 20:51:40 $");
 script_end_attributes();

 
 summary["english"] = "Checks for patch PHSS_26137";
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

if ( hpux_patch_installed (patches:"PHSS_26137 PHSS_27857 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"OVSNMPAgent.MASTER", version:"	OVSNMPAgent.MASTER,B.10.27.00 OVSNMPAgent.MASTER,B.10.26.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVSNMPAgent.MASTER", version:"	OVSNMPAgent.MASTER,B.11.00.00 OVSNMPAgent.MASTER,B.11.01.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVSNMPAgent.MASTER", version:"	OVSNMPAgent.MASTER,B.11.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVSNMPAgent.SNMP-ENG-A-MAN", version:"	OVSNMPAgent.SNMP-ENG-A-MAN,B.10.27.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVSNMPAgent.SNMP-ENG-A-MAN", version:"	OVSNMPAgent.SNMP-ENG-A-MAN,B.10.26.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVSNMPAgent.SNMP-ENG-A-MAN", version:"	OVSNMPAgent.SNMP-ENG-A-MAN,B.11.00.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVSNMPAgent.SNMP-ENG-A-MAN", version:"	OVSNMPAgent.SNMP-ENG-A-MAN,B.11.01.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVSNMPAgent.SNMP-ENG-A-MAN", version:"	OVSNMPAgent.SNMP-ENG-A-MAN,B.11.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVSNMPAgent.SUBAGT-HPUNIX", version:"	OVSNMPAgent.SUBAGT-HPUNIX,B.10.27.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVSNMPAgent.SUBAGT-HPUNIX", version:"	OVSNMPAgent.SUBAGT-HPUNIX,B.10.26.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVSNMPAgent.SUBAGT-HPUNIX", version:"	OVSNMPAgent.SUBAGT-HPUNIX,B.11.00.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVSNMPAgent.SUBAGT-HPUNIX", version:"	OVSNMPAgent.SUBAGT-HPUNIX,B.11.01.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVSNMPAgent.SUBAGT-HPUNIX", version:"	OVSNMPAgent.SUBAGT-HPUNIX,B.11.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVSNMPAgent.SUBAGT-MIB2", version:"	OVSNMPAgent.SUBAGT-MIB2,B.10.27.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVSNMPAgent.SUBAGT-MIB2", version:"	OVSNMPAgent.SUBAGT-MIB2,B.10.26.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVSNMPAgent.SUBAGT-MIB2", version:"	OVSNMPAgent.SUBAGT-MIB2,B.11.00.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVSNMPAgent.SUBAGT-MIB2", version:"	OVSNMPAgent.SUBAGT-MIB2,B.11.01.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVSNMPAgent.SUBAGT-MIB2", version:"	OVSNMPAgent.SUBAGT-MIB2,B.11.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVSNMPAgentMan.AGENT-MAN", version:"	OVSNMPAgentMan.AGENT-MAN,B.10.27.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVSNMPAgentMan.AGENT-MAN", version:"	OVSNMPAgentMan.AGENT-MAN,B.10.26.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVSNMPAgentMan.AGENT-MAN", version:"	OVSNMPAgentMan.AGENT-MAN,B.11.00.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVSNMPAgentMan.AGENT-MAN", version:"	OVSNMPAgentMan.AGENT-MAN,B.11.01.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OVSNMPAgentMan.AGENT-MAN", version:"	OVSNMPAgentMan.AGENT-MAN,B.11.11.00") )
{
 security_hole(0);
 exit(0);
}
