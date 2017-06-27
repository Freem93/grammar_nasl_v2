#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(24845);
  script_version("$Revision: 1.26 $");
  script_cvs_date("$Date: 2016/12/09 21:04:55 $");

  script_cve_id("CVE-2007-2138", "CVE-2009-0922", "CVE-2009-3229", "CVE-2009-3230");

  script_name(english:"Solaris 10 (sparc) : 123590-12");
  script_summary(english:"Check for patch 123590-12");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 123590-12"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SunOS 5.10: PostgreSQL patch.
Date this patch was last updated by Sun : Jan/14/10"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/123590-12"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_cwe_id(264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/03/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"123590-12", obsoleted_by:"", package:"SUNWpostgr-pl", version:"11.10.0,REV=2006.03.22.04.24") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"123590-12", obsoleted_by:"", package:"SUNWpostgr-libs", version:"11.10.0,REV=2006.03.22.04.24") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"123590-12", obsoleted_by:"", package:"SUNWpostgr-docs", version:"11.10.0,REV=2006.03.22.04.24") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"123590-12", obsoleted_by:"", package:"SUNWpostgr-server-data", version:"11.10.0,REV=2006.03.22.04.24") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"123590-12", obsoleted_by:"", package:"SUNWpostgr-tclS", version:"11.10.0,REV=2006.03.22.04.24") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"123590-12", obsoleted_by:"", package:"SUNWpostgr-devel", version:"11.10.0,REV=2006.03.22.04.24") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"123590-12", obsoleted_by:"", package:"SUNWpostgrS", version:"11.10.0,REV=2006.03.22.04.24") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"123590-12", obsoleted_by:"", package:"SUNWpostgr-tcl", version:"11.10.0,REV=2006.03.22.04.24") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"123590-12", obsoleted_by:"", package:"SUNWpostgr-server", version:"11.10.0,REV=2006.03.22.04.24") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"123590-12", obsoleted_by:"", package:"SUNWpostgr-jdbcS", version:"11.10.0,REV=2006.03.22.04.24") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"123590-12", obsoleted_by:"", package:"SUNWpostgr-jdbc", version:"11.10.0,REV=2006.03.22.04.24") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"123590-12", obsoleted_by:"", package:"SUNWpostgr", version:"11.10.0,REV=2006.03.22.04.24") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"123590-12", obsoleted_by:"", package:"SUNWpostgr-contrib", version:"11.10.0,REV=2006.03.22.04.24") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
