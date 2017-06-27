#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(76517);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/07/19 18:32:15 $");

  script_name(english:"Solaris 10 (sparc) : 151009-92");
  script_summary(english:"Check for patch 151009-92");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 151009-92"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"JavaSE 8: update 92 patch (equivalent to J.
Date this patch was last updated by Sun : Apr/18/16"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/151009-92"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"151009-92", obsoleted_by:"152100-01 ", package:"SUNWj8man", version:"1.8.0,REV=2014.03.18.08.02") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"151009-92", obsoleted_by:"152100-01 ", package:"SUNWj8jmp", version:"1.8.0,REV=2014.03.18.08.02") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"151009-92", obsoleted_by:"152100-01 ", package:"SUNWj8rt", version:"1.8.0,REV=2014.03.18.08.02") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"151009-92", obsoleted_by:"152100-01 ", package:"SUNWj8dev", version:"1.8.0,REV=2014.03.18.08.02") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"151009-92", obsoleted_by:"152100-01 ", package:"SUNWj8cfg", version:"1.8.0,REV=2014.03.18.08.02") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"151009-92", obsoleted_by:"152100-01 ", package:"SUNWj8dmo", version:"1.8.0,REV=2014.03.18.08.02") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
