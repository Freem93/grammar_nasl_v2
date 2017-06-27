#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
 script_id(56705);
 script_version("$Revision: 1.1 $");
 script_cvs_date("$Date: 2011/11/04 10:50:46 $");
 
 script_name(english:"HP-UX Security Patch : PHKL_41421");
 script_summary(english:"Checks for patch in swlist output");

 script_set_attribute(attribute:"synopsis", value: 
"The remote HP-UX host is missing a security-related patch.");
 script_set_attribute(attribute:"description", value:
"vfs_scalls override_umask,cumulative patch");
 script_set_attribute(attribute:"solution", value:"This patch has been superseded by the following patch : PHKL_42310.");
 script_set_attribute(attribute:"risk_factor", value:"High");
 
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");
 script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/04");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2011 Tenable Network Security, Inc.");
 script_family(english:"HP-UX Local Security Checks");

 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/HP-UX/swlist");
 exit(0);
}

include("hpux.inc");
# this patch is no longer a security fix
exit(0);

