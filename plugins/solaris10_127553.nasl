#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(35194);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/09 21:04:55 $");

  script_cve_id("CVE-2008-5422", "CVE-2008-5423", "CVE-2009-2489", "CVE-2009-2490", "CVE-2009-2491", "CVE-2009-4294", "CVE-2009-4295");

  script_name(english:"Solaris 10 (sparc) : 127553-08");
  script_summary(english:"Check for patch 127553-08");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 127553-08"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Sun Ray Core Services version 4.0 Patch Update.
Date this patch was last updated by Sun : Feb/24/10"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/127553-08"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(200, 264, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"127553-08", obsoleted_by:"", package:"SUNWlibusbut", version:"4.0_48,REV=2007.08.01.15.08") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"127553-08", obsoleted_by:"", package:"SUNWutm", version:"4.0_48,REV=2007.08.01.15.08") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"127553-08", obsoleted_by:"", package:"SUNWuto", version:"4.0_48,REV=2007.08.01.15.08") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"127553-08", obsoleted_by:"", package:"SUNWutscr", version:"4.0_48,REV=2007.08.01.15.08") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"127553-08", obsoleted_by:"", package:"SUNWutr", version:"4.0_48,REV=2007.08.01.15.08") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"127553-08", obsoleted_by:"", package:"SUNWutu", version:"4.0_48,REV=2007.08.01.15.08") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"127553-08", obsoleted_by:"", package:"SUNWutgsm", version:"4.0_48,REV=2007.08.01.15.08") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"127553-08", obsoleted_by:"", package:"SUNWutref", version:"4.0_48,REV=2007.08.01.15.08") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"127553-08", obsoleted_by:"", package:"SUNWutfw", version:"4.0_48,REV=2007.08.01.15.08") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"127553-08", obsoleted_by:"", package:"SUNWutsto", version:"4.0_48,REV=2007.08.01.15.08") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"127553-08", obsoleted_by:"", package:"SUNWuta", version:"4.0_48,REV=2007.08.01.15.08") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
