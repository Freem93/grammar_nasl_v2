#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(34068);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2014/08/30 00:33:50 $");

  script_name(english:"Solaris 8 (sparc) : 139093-03");
  script_summary(english:"Check for patch 139093-03");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 139093-03"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"GNOME 2.0.0: SUNWTiff libtiff library patch.
Date this patch was last updated by Sun : Mar/19/12"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/139093-03"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/09/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2014 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"139093-03", obsoleted_by:"", package:"SUNWTiffx", version:"1.0.0,REV=2003.01.14.12.39") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"139093-03", obsoleted_by:"", package:"SUNWTiff", version:"6.4.1.40,REV=0.2002.12.09") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
