#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(23346);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2014/08/30 00:33:49 $");

  script_cve_id("CVE-2003-1576");

  script_name(english:"Solaris 8 (sparc) : 113105-01");
  script_summary(english:"Check for patch 113105-01");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 113105-01"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Change Management 1.0: Patch for Solaris 8.
Date this patch was last updated by Sun : May/15/03"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/113105-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/05/15");
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

if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"113105-01", obsoleted_by:"", package:"SUNWicapp", version:"1.0.0,REV=2002.10.15.18.02") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"113105-01", obsoleted_by:"", package:"SUNWicsvc", version:"2002.10.15.18.02") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"113105-01", obsoleted_by:"", package:"SUNWmcon", version:"1.0,REV=2002.10.11.05.05") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"113105-01", obsoleted_by:"", package:"SUNWicam", version:"2002.10.15.18.02") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
