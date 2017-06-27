#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(30175);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2016/12/09 21:14:08 $");

  script_cve_id("CVE-2009-0922", "CVE-2009-3229", "CVE-2009-3230", "CVE-2010-4015");
  script_bugtraq_id(46084);
  script_osvdb_id(70740);

  script_name(english:"Solaris 10 (x86) : 136999-10");
  script_summary(english:"Check for patch 136999-10");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 136999-10"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SunOS 5.10_x86: PostgreSQL 8.2 core patch.
Date this patch was last updated by Sun : Jun/09/11"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/136999-10"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/05");
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

if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"136999-10", obsoleted_by:"", package:"SUNWpostgr-82-contrib", version:"11.10.0,REV=2007.04.27.11.07") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"136999-10", obsoleted_by:"", package:"SUNWpostgr-82-server-data-root", version:"11.10.0,REV=2007.04.27.11.07") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"136999-10", obsoleted_by:"", package:"SUNWpostgr-82-server", version:"11.10.0,REV=2007.04.27.11.07") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"136999-10", obsoleted_by:"", package:"SUNWpostgr-82-pl", version:"11.10.0,REV=2007.04.27.11.07") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"136999-10", obsoleted_by:"", package:"SUNWpostgr-82-devel", version:"11.10.0,REV=2007.04.27.11.07") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"136999-10", obsoleted_by:"", package:"SUNWpostgr-82-libs", version:"11.10.0,REV=2007.04.27.11.07") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"136999-10", obsoleted_by:"", package:"SUNWpostgr-82-client", version:"11.10.0,REV=2007.04.27.11.07") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
