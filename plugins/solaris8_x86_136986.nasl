#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(31599);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2014/08/30 00:39:38 $");

  script_cve_id("CVE-2008-1286", "CVE-2008-5550");

  script_name(english:"Solaris 8 (x86) : 136986-03");
  script_summary(english:"Check for patch 136986-03");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 136986-03"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Sun Java Web Console 3.0.2_x86: Security fixes.
Date this patch was last updated by Sun : Jun/25/09"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/136986-03"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/17");
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

if (solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"136986-03", obsoleted_by:"", package:"SUNWmctag", version:"3.0.2,REV=2006.12.08.20.48") < 0) flag++;
if (solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"136986-03", obsoleted_by:"", package:"SUNWmcos", version:"3.0.2,REV=2006.12.08.20.48") < 0) flag++;
if (solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"136986-03", obsoleted_by:"", package:"SUNWmcon", version:"3.0.2,REV=2006.12.08.20.48") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
