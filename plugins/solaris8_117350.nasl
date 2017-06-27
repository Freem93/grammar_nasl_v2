#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(20945);
  script_version("$Revision: 1.58 $");
  script_cvs_date("$Date: 2016/12/09 21:14:09 $");

  script_cve_id("CVE-2006-5012", "CVE-2007-5632", "CVE-2008-1115", "CVE-2008-3875", "CVE-2008-4160", "CVE-2009-0132", "CVE-2009-0874", "CVE-2009-0875");

  script_name(english:"Solaris 8 (sparc) : 117350-62");
  script_summary(english:"Check for patch 117350-62");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 117350-62"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SunOS 5.8: kernel patch.
Date this patch was last updated by Sun : Apr/21/09"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/117350-62"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(78, 189, 264, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/02/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"117350-62", obsoleted_by:"", package:"SUNWhea", version:"11.8.0,REV=2000.01.08.18.12") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"117350-62", obsoleted_by:"", package:"SUNWcar", version:"11.8.0,REV=2000.01.13.13.40") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"117350-62", obsoleted_by:"", package:"SUNWcarx", version:"11.8.0,REV=2000.01.13.13.40") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"117350-62", obsoleted_by:"", package:"FJSVhea", version:"1.0,REV=1999.12.23.19.10") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"117350-62", obsoleted_by:"", package:"SUNWmdbx", version:"11.8.0,REV=2000.01.08.18.12") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"117350-62", obsoleted_by:"", package:"SUNWpmux", version:"11.8.0,REV=2000.01.08.18.12") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"117350-62", obsoleted_by:"", package:"SUNWcsxu", version:"11.8.0,REV=2000.01.08.18.12") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"117350-62", obsoleted_by:"", package:"SUNWpmu", version:"11.8.0,REV=2000.01.08.18.12") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"117350-62", obsoleted_by:"", package:"SUNWcprx", version:"11.8.0,REV=2000.01.08.18.12") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"117350-62", obsoleted_by:"", package:"SUNWcsu", version:"11.8.0,REV=2000.01.08.18.12") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"117350-62", obsoleted_by:"", package:"SUNWmdb", version:"11.8.0,REV=2000.01.08.18.12") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"117350-62", obsoleted_by:"", package:"SUNWcsr", version:"11.8.0,REV=2000.01.08.18.12") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"117350-62", obsoleted_by:"", package:"SUNWcpr", version:"11.8.0,REV=2000.01.08.18.12") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
