#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(76070);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/10/08 11:23:30 $");

  script_cve_id("CVE-2014-0397");
  script_bugtraq_id(65819);
  script_osvdb_id(103780);

  script_name(english:"Solaris 10 (sparc) : 123611-05");
  script_summary(english:"Check for patch 123611-05");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 123611-05"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"X11 6.6.2: Trusted Extensions patch.
Date this patch was last updated by Sun : Jun/14/14"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/123611-05"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/16");
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

if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"123611-05", obsoleted_by:"", package:"SUNWxwinc", version:"6.6.2.7400,REV=0.2004.12.15") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"123611-05", obsoleted_by:"", package:"SUNWxwplt", version:"6.6.2.7400,REV=0.2004.12.15") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"123611-05", obsoleted_by:"", package:"SUNWxwrtl", version:"6.6.2.7400,REV=0.2004.12.15") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
