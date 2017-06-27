#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(13588);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2014/08/30 00:45:31 $");

  script_cve_id("CVE-2008-5519");

  script_name(english:"Solaris 9 (x86) : 114017-07");
  script_summary(english:"Check for patch 114017-07");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 114017-07"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SunOS 5.9_x86: tomcat security patch.
Date this patch was last updated by Sun : May/27/11"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/114017-07"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_cwe_id(200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"114017-07", obsoleted_by:"", package:"SUNWtcatu", version:"11.9.0,REV=2002.03.02.00.30") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"114017-07", obsoleted_by:"", package:"SUNWtcatr", version:"11.9.0,REV=2002.03.02.00.30") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"114017-07", obsoleted_by:"", package:"SUNWtcatS", version:"11.9.0,REV=2002.03.02.00.30") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:solaris_get_report());
  else security_note(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
