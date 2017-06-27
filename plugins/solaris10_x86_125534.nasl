#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(41944);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2017/02/10 14:51:43 $");

  script_cve_id("CVE-2012-3199");

  script_name(english:"Solaris 10 (x86) : 125534-19");
  script_summary(english:"Check for patch 125534-19");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 125534-19"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Vulnerability in the Solaris component of Oracle Sun Products Suite
(subcomponent: Gnome Trusted Extension). Supported versions that are
affected are 10 and 11. Easily exploitable vulnerability requiring
logon to Operating System. Successful attack of this vulnerability can
result in unauthorized Operating System takeover including arbitrary
code execution."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/125534-19"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"125534-19", obsoleted_by:"", package:"SUNWtgnome-tsol-libs-devel", version:"2.6.0,REV=101.0.3.2006.09.05.04.14") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"125534-19", obsoleted_by:"", package:"SUNWtgnome-xagent", version:"2.6.0,REV=101.0.3.2006.10.16.10.31") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"125534-19", obsoleted_by:"", package:"SUNWtgnome-tsoljdsselmgr", version:"2.6.0,REV=101.0.3.2006.10.16.04.15") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"125534-19", obsoleted_by:"", package:"SUNWtgnome-tstripe", version:"2.6,REV=101.0.3.2006.11.10.16.12") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"125534-19", obsoleted_by:"", package:"SUNWtgnome-tsol-libs", version:"2.6.0,REV=101.0.3.2006.09.05.04.14") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"125534-19", obsoleted_by:"", package:"SUNWtgnome-tsoljdsdevmgr", version:"2.6,REV=101.0.3.2006.10.16.04.14") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"125534-19", obsoleted_by:"", package:"SUNWtgnome-tsoljdslabel", version:"2.6.0,REV=101.0.3.2006.11.08.04.15") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
