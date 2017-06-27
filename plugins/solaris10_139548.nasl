#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(71815);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/30 00:06:19 $");

  script_cve_id("CVE-2009-4314");

  script_name(english:"Solaris 10 (sparc) : 139548-07");
  script_summary(english:"Check for patch 139548-07");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 139548-07"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Sun Ray Core Services version 4.1 Patch Update.
Date this patch was last updated by Sun : Sep/16/10"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/139548-07"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"139548-07", obsoleted_by:"", package:"SUNWlibusbut", version:"4.1_50,REV=2008.09.25.12.37") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"139548-07", obsoleted_by:"", package:"SUNWutm", version:"4.1_50,REV=2008.09.25.12.37") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"139548-07", obsoleted_by:"", package:"SUNWuto", version:"4.1_50,REV=2008.09.25.12.37") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"139548-07", obsoleted_by:"", package:"SUNWutps", version:"4.1_50,REV=2008.09.25.12.37") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"139548-07", obsoleted_by:"", package:"SUNWutscr", version:"4.1_50,REV=2008.09.25.12.37") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"139548-07", obsoleted_by:"", package:"SUNWutr", version:"4.1_50,REV=2008.09.25.12.37") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"139548-07", obsoleted_by:"", package:"SUNWutk", version:"4.1_50,REV=2008.09.25.12.37") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"139548-07", obsoleted_by:"", package:"SUNWutxsun", version:"4.1_50,REV=2008.09.25.12.37") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"139548-07", obsoleted_by:"", package:"SUNWutgsm", version:"4.1_50,REV=2008.09.25.12.37") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"139548-07", obsoleted_by:"", package:"SUNWutref", version:"4.1_50,REV=2008.09.25.12.37") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"139548-07", obsoleted_by:"", package:"SUNWutfw", version:"4.1_50,REV=2008.09.25.12.37") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"139548-07", obsoleted_by:"", package:"SUNWutsto", version:"4.1_50,REV=2008.09.25.12.37") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"139548-07", obsoleted_by:"", package:"SUNWuta", version:"4.1_50,REV=2008.09.25.12.37") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
