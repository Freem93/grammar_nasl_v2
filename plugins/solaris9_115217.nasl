#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24993);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/03/23 15:13:14 $");

  script_name(english:"Solaris 9 (sparc) : 115217-05");
  script_summary(english:"Check for patch 115217-05.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security patch.");
  script_set_attribute(attribute:"description", value:
"Version 4.0 of Volume Manager on the remote Solaris 9 host is missing
security patch 115217-05 for package VRTSvxvm.");
  script_set_attribute(attribute:"see_also", value:"https://sort.symantec.com/patch/detail/762");
  script_set_attribute(attribute:"see_also", value:"http://www.symantec.com/theme.jsp?themeid=sun-support");
  script_set_attribute(attribute:"solution", value:
"Install the 4.0 MP2a Maintenance Pack provided by Symantec, which
includes the 115217-05 patch.");
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/04/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

vendornote = '\nThis patch is no longer available from Oracle, as the Symantec Veritas\n' +
'Volume Manager support contract with Oracle has ended. The patch has\n' +
'been removed from Oracle repositories.\n\n' +
'Please visit https://sort.symantec.com/patch/detail/762 to download\n' +
'the patch.\n' +
'Please contact the vendor for product support :\n' +
'http://www.symantec.com/theme.jsp?themeid=sun-support';

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"115217-05", obsoleted_by:"", package:"VRTSvxvm", version:"4.0,REV=12.06.2003.01.35") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report() + vendornote);
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
