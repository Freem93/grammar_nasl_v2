#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(58737);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2017/05/16 13:59:27 $");

  script_cve_id("CVE-2013-5839", "CVE-2014-0390");
  script_bugtraq_id(63078, 64859);
  script_osvdb_id(98502);

  script_name(english:"Solaris 10 (x86) : 147674-11");
  script_summary(english:"Check for patch 147674-11");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 147674-11"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SunOS 5.10_x86: Oracle Java Web Console 3.1 Patch.
Date this patch was last updated by Sun : May/11/17"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/147674-11"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"147674-11", obsoleted_by:"", package:"SUNWmctag", version:"3.0.2,REV=2006.12.08.20.48") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"147674-11", obsoleted_by:"", package:"SUNWmcosx", version:"3.0.2,REV=2006.12.08.23.39") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"147674-11", obsoleted_by:"", package:"SUNWmconr", version:"3.0.2,REV=2006.12.08.23.39") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"147674-11", obsoleted_by:"", package:"SUNWmcos", version:"3.0.2,REV=2006.12.08.23.39") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"147674-11", obsoleted_by:"", package:"SUNWmcon", version:"3.0.2,REV=2006.12.08.20.48") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
