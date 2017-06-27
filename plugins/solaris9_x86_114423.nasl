#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(22248);
  script_version("$Revision: 1.25 $");
  script_cvs_date("$Date: 2014/08/30 01:27:20 $");

  script_cve_id("CVE-2006-4319", "CVE-2008-2144");
  script_bugtraq_id(29135);
  script_xref(name:"IAVT", value:"2008-T-0021");

  script_name(english:"Solaris 9 (x86) : 114423-09");
  script_summary(english:"Check for patch 114423-09");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 114423-09"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SunOS 5.9_x86: format, lp, IKE patch.
Date this patch was last updated by Sun : Mar/18/11"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/114423-09"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/08/21");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"114423-09", obsoleted_by:"", package:"SUNWcstl", version:"11.9.0,REV=2002.11.04.02.51") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"114423-09", obsoleted_by:"", package:"SUNWscplp", version:"13.1,REV=2002.11.04.02.51") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"114423-09", obsoleted_by:"", package:"SUNWpsf", version:"13.1,REV=2002.11.04.02.51") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"114423-09", obsoleted_by:"", package:"SUNWpsr", version:"13.1,REV=2002.11.04.02.51") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"114423-09", obsoleted_by:"", package:"SUNWpsu", version:"13.1,REV=2002.11.04.02.51") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"114423-09", obsoleted_by:"", package:"SUNWcsu", version:"11.9.0,REV=2002.11.04.02.51") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"114423-09", obsoleted_by:"", package:"SUNWppm", version:"11.9.0,REV=2002.11.04.02.51") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"114423-09", obsoleted_by:"", package:"SUNWcsr", version:"11.9.0,REV=2002.11.04.02.51") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"114423-09", obsoleted_by:"", package:"SUNWpcu", version:"13.1,REV=2002.11.04.02.51") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"114423-09", obsoleted_by:"", package:"SUNWcsl", version:"11.9.0,REV=2002.11.04.02.51") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
