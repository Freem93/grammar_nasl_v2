#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(18068);
  script_version("$Revision: 1.31 $");
  script_cvs_date("$Date: 2014/08/30 00:17:44 $");

  script_cve_id("CVE-2007-0957");

  script_name(english:"Solaris 8 (sparc) : 109223-10");
  script_summary(english:"Check for patch 109223-10");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 109223-10"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SunOS 5.8: kpasswd, libgss.so.1 and libkad.
Date this patch was last updated by Sun : Aug/03/07"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://download.oracle.com/sunalerts/1017350.1.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/17");
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

if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"109223-10", obsoleted_by:"", package:"SUNWcstlx", version:"11.8.0,REV=2000.01.08.18.12") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"109223-10", obsoleted_by:"", package:"SUNWgssx", version:"11.8.0,REV=2000.01.08.18.12") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"109223-10", obsoleted_by:"", package:"SUNWcstl", version:"11.8.0,REV=2000.01.08.18.12") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"109223-10", obsoleted_by:"", package:"SUNWgss", version:"11.8.0,REV=2000.01.08.18.12") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"109223-10", obsoleted_by:"", package:"SUNWcsu", version:"11.8.0,REV=2000.01.08.18.12") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"109223-10", obsoleted_by:"", package:"SUNWcslx", version:"11.8.0,REV=2000.01.08.18.12") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"109223-10", obsoleted_by:"", package:"SUNWcsl", version:"11.8.0,REV=2000.01.08.18.12") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
