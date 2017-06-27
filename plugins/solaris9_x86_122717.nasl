#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(52734);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/08/30 00:50:08 $");

  script_cve_id("CVE-2011-0839");

  script_name(english:"Solaris 9 (x86) : 122717-02");
  script_summary(english:"Check for patch 122717-02");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 122717-02"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SunOS 5.9_x86: kernel/fs/lofs patch.
Date this patch was last updated by Sun : Mar/18/11"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/122717-02"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:M/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"122717-02", obsoleted_by:"", package:"SUNWmdb", version:"11.9.0,REV=2002.11.04.02.51") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"122717-02", obsoleted_by:"", package:"SUNWhea", version:"11.9.0,REV=2002.11.04.02.51") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"122717-02", obsoleted_by:"", package:"SUNWcsr", version:"11.9.0,REV=2002.11.04.02.51") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:solaris_get_report());
  else security_note(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
