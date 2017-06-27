#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(29850);
  script_version("$Revision: 1.25 $");
  script_cvs_date("$Date: 2014/08/30 00:39:38 $");

  script_cve_id("CVE-2009-0319", "CVE-2009-2029");

  script_name(english:"Solaris 8 (x86) : 128625-11");
  script_summary(english:"Check for patch 128625-11");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 128625-11"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SunOS 5.8_x86: LDAP2 client, libc, libthre.
Date this patch was last updated by Sun : Mar/09/09"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/128625-11"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2014 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"128625-11", obsoleted_by:"", package:"SUNWpppd", version:"11.8.0,REV=2001.02.21.14.14") < 0) flag++;
if (solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"128625-11", obsoleted_by:"", package:"SUNWcsu", version:"11.8.0,REV=2000.01.08.18.17") < 0) flag++;
if (solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"128625-11", obsoleted_by:"", package:"SUNWnisr", version:"11.8.0,REV=2000.01.08.18.17") < 0) flag++;
if (solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"128625-11", obsoleted_by:"", package:"SUNWapppr", version:"11.8.0,REV=2000.01.08.18.17") < 0) flag++;
if (solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"128625-11", obsoleted_by:"", package:"SUNWpppdu", version:"11.8.0,REV=2001.02.21.14.14") < 0) flag++;
if (solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"128625-11", obsoleted_by:"", package:"SUNWpppdr", version:"11.8.0,REV=2001.02.21.14.14") < 0) flag++;
if (solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"128625-11", obsoleted_by:"", package:"SUNWcstl", version:"11.8.0,REV=2000.01.08.18.17") < 0) flag++;
if (solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"128625-11", obsoleted_by:"", package:"SUNWatfsr", version:"11.8.0,REV=2000.01.08.18.17") < 0) flag++;
if (solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"128625-11", obsoleted_by:"", package:"SUNWarc", version:"11.8.0,REV=2000.01.08.18.17") < 0) flag++;
if (solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"128625-11", obsoleted_by:"", package:"SUNWlldap", version:"11.8.0,REV=2000.01.08.18.17") < 0) flag++;
if (solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"128625-11", obsoleted_by:"", package:"SUNWapppu", version:"11.8.0,REV=2000.01.08.18.17") < 0) flag++;
if (solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"128625-11", obsoleted_by:"", package:"SUNWdpl", version:"11.8.0,REV=2000.01.08.18.17") < 0) flag++;
if (solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"128625-11", obsoleted_by:"", package:"SUNWmdb", version:"11.8.0,REV=2000.01.08.18.17") < 0) flag++;
if (solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"128625-11", obsoleted_by:"", package:"SUNWhea", version:"11.8.0,REV=2000.01.08.18.17") < 0) flag++;
if (solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"128625-11", obsoleted_by:"", package:"SUNWnisu", version:"11.8.0,REV=2000.01.08.18.17") < 0) flag++;
if (solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"128625-11", obsoleted_by:"", package:"SUNWpppgS", version:"11.8.0,REV=2001.02.21.14.14") < 0) flag++;
if (solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"128625-11", obsoleted_by:"", package:"SUNWcsr", version:"11.8.0,REV=2000.01.08.18.17") < 0) flag++;
if (solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"128625-11", obsoleted_by:"", package:"SUNWatfsu", version:"11.8.0,REV=2000.01.08.18.17") < 0) flag++;
if (solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"128625-11", obsoleted_by:"", package:"SUNWcsl", version:"11.8.0,REV=2000.01.08.18.17") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
