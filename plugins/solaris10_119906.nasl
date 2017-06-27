#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(71645);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/30 00:06:18 $");

  script_name(english:"Solaris 10 (sparc) : 119906-21");
  script_summary(english:"Check for patch 119906-21");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 119906-21"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"GNOME 2.6.0: Virtual File System Framework patch.
Date this patch was last updated by Sun : Jul/11/13"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/119906-21"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"119906-21", obsoleted_by:"", package:"SUNWgnome-vfs-devel", version:"2.6.0,REV=10.0.3.2004.12.15.17.07") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"119906-21", obsoleted_by:"", package:"SUNWgnome-vfs-share", version:"2.6.0,REV=10.0.3.2004.12.15.17.07") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"119906-21", obsoleted_by:"", package:"SUNWgnome-vfs", version:"2.6.0,REV=10.0.3.2004.12.15.17.07") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
