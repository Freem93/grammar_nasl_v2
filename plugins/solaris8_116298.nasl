#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(23378);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2014/08/30 00:33:49 $");

  script_name(english:"Solaris 8 (sparc) : 116298-21");
  script_summary(english:"Check for patch 116298-21");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 116298-21"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Sun One Application Server 7.0: Java API for XML Parsing 1.2 Patch.
Date this patch was last updated by Sun : May/23/06"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/116298-21"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/11/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"116298-21", obsoleted_by:"", package:"SUNWxrpcrt", version:"7.0,REV=2003.05.07.00.23") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"116298-21", obsoleted_by:"", package:"SUNWxsrt", version:"7.0,REV=2003.05.07.00.23") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"116298-21", obsoleted_by:"", package:"SUNWxrgrt", version:"7.0,REV=2003.05.07.00.23") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
