#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(16089);
  script_version("$Revision: 1.33 $");
  script_cvs_date("$Date: 2014/08/30 00:39:39 $");

  script_cve_id("CVE-2007-3093", "CVE-2007-3094", "CVE-2011-0790");

  script_name(english:"Solaris 9 (sparc) : 112945-46");
  script_summary(english:"Check for patch 112945-46");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 112945-46"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SunOS 5.9: wbem Patch.
Date this patch was last updated by Sun : Aug/01/07"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/112945-46"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112945-46", obsoleted_by:"", package:"SUNWmga", version:"1.0,REV=2002.04.14.23.49") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112945-46", obsoleted_by:"", package:"SUNWmccom", version:"11.9,REV=2002.04.14.23.49") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112945-46", obsoleted_by:"", package:"SUNWwbdev", version:"2.5,REV=2002.04.14.23.49") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112945-46", obsoleted_by:"", package:"SUNWwbpro", version:"2.0,REV=2002.04.14.23.49") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112945-46", obsoleted_by:"", package:"SUNWmc", version:"11.9,REV=2002.04.14.23.49") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112945-46", obsoleted_by:"", package:"SUNWdclnt", version:"1.0,REV=2002.04.14.23.49") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112945-46", obsoleted_by:"", package:"SUNWpmgr", version:"3.0,REV=2002.04.14.23.49") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112945-46", obsoleted_by:"", package:"SUNWwbcou", version:"2.5,REV=2002.04.14.23.49") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112945-46", obsoleted_by:"", package:"SUNWwbapi", version:"2.5,REV=2002.04.14.23.49") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112945-46", obsoleted_by:"", package:"SUNWwbcor", version:"2.5,REV=2002.04.14.23.49") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112945-46", obsoleted_by:"", package:"SUNWmcc", version:"11.9,REV=2002.04.14.23.49") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112945-46", obsoleted_by:"", package:"SUNWwbmc", version:"11.9,REV=2002.04.14.23.49") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112945-46", obsoleted_by:"", package:"SUNWlvma", version:"1.0,REV=2002.04.14.23.49") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
