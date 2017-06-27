#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(23603);
  script_version("$Revision: 1.25 $");
  script_cvs_date("$Date: 2014/08/30 00:45:32 $");

  script_cve_id("CVE-2007-2267");

  script_name(english:"Solaris 9 (x86) : 117909-43");
  script_summary(english:"Check for patch 117909-43");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 117909-43"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Sun Cluster 3.1_x86: Core Patch for Solaris 9_x86.
Date this patch was last updated by Sun : Dec/08/11"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/117909-43"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/08");
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

if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"117909-43", obsoleted_by:"", package:"SUNWscu", version:"3.1.0,REV=2004.04.01.21.47") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"117909-43", obsoleted_by:"", package:"SUNWscsal", version:"3.1.0,REV=2004.04.01.21.47") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"117909-43", obsoleted_by:"", package:"SUNWscdev", version:"3.1.0,REV=2004.04.01.21.47") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"117909-43", obsoleted_by:"", package:"SUNWccon", version:"3.1.0,REV=2004.04.01.21.47") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"117909-43", obsoleted_by:"", package:"SUNWscman", version:"3.1.0,REV=2004.04.01.21.47") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"117909-43", obsoleted_by:"", package:"SUNWscr", version:"3.1.0,REV=2004.04.01.21.47") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"117909-43", obsoleted_by:"", package:"SUNWscgds", version:"3.1.0,REV=2004.04.01.21.47") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
