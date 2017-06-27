#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_37182. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(28270);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2014/03/12 15:42:18 $");

  script_cve_id("CVE-2007-3698", "CVE-2007-3922");
  script_osvdb_id(36662, 36663);
  script_xref(name:"HP", value:"emr_na-c01269450");
  script_xref(name:"HP", value:"SSRT071465");

  script_name(english:"HP-UX PHSS_37182 : HP OpenView Operations (OVO) Running on HP-UX and Solaris, Remote Unauthorized Access, Denial of Service (DoS) (HPSBMA02288 SSRT071465 rev.1)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.X OV OVO8.X IA-64 JavaGUI client A.08.27 : 

Potential security vulnerabilities have been identified in OpenView
Operations (OVO) running on HP-UX and Solaris. These vulnerabilities
may be exploited remotely to gain unauthorized access or to create a
Denial of Service (DoS). References: SUN Alert 102995, 102997,
CVE-2007-3922, CVE-2007-3698."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01269450
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?88bac98f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_37182 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/20");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
  script_family(english:"HP-UX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/HP-UX/version", "Host/HP-UX/swlist");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("hpux.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/HP-UX/version")) audit(AUDIT_OS_NOT, "HP-UX");
if (!get_kb_item("Host/HP-UX/swlist")) audit(AUDIT_PACKAGE_LIST_MISSING);

if (!hpux_check_ctx(ctx:"11.23 11.31", proc:"ia64"))
{
  exit(0, "The host is not affected since PHSS_37182 applies to a different OS release / architecture.");
}

patches = make_list("PHSS_37182", "PHSS_37565", "PHSS_38202", "PHSS_38853", "PHSS_39326", "PHSS_39895", "PHSS_40467", "PHSS_41212");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"OVOPC-WWW.OVOPC-WWW-ENG", version:"A.08.20.050")) flag++;
if (hpux_check_patch(app:"OVOPC-WWW.OVOPC-WWW-GUI", version:"A.08.20.050")) flag++;
if (hpux_check_patch(app:"OVOPC-WWW.OVOPC-WWW-JPN", version:"A.08.20.050")) flag++;
if (hpux_check_patch(app:"OVOPC-WWW.OVOPC-WWW-KOR", version:"A.08.20.050")) flag++;
if (hpux_check_patch(app:"OVOPC-WWW.OVOPC-WWW-SCH", version:"A.08.20.050")) flag++;
if (hpux_check_patch(app:"OVOPC-WWW.OVOPC-WWW-SPA", version:"A.08.20.050")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
