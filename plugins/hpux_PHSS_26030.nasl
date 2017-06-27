#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_26030. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(16581);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2014/02/25 02:41:51 $");

  script_cve_id("CVE-2001-0803");
  script_bugtraq_id(3517);
  script_osvdb_id(4503);
  script_xref(name:"HP", value:"emr_na-c00994317");
  script_xref(name:"HP", value:"HPSBUX00175");
  script_xref(name:"HP", value:"SSRT071388");

  script_name(english:"HP-UX PHSS_26030 : HP-UX running CDE dtspcd, Remote Unauthorized Access, Increased Privilege, Arbitrary Code Execution (HPSBUX00175 SSRT071388 rev.5)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.04 (VVOS) CDE Runtime DEC2001 Periodic Patch : 

Buffer overflow in dtspcd."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00994317
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1c8376bc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_26030 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Solaris dtspcd Heap Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/01/31");
  script_set_attribute(attribute:"patch_modification_date", value:"2007/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/16");
  script_set_attribute(attribute:"vuln_publication_date", value:"2002/07/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
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

if (!hpux_check_ctx(ctx:"11.04"))
{
  exit(0, "The host is not affected since PHSS_26030 applies to a different OS release.");
}

patches = make_list("PHSS_26030", "PHSS_28174", "PHSS_29214", "PHSS_30167", "PHSS_30807");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"CDE.CDE-DTTERM", version:"B.11.04")) flag++;
if (hpux_check_patch(app:"CDE.CDE-ENG-A-HELP", version:"B.11.04")) flag++;
if (hpux_check_patch(app:"CDE.CDE-ENG-A-MAN", version:"B.11.04")) flag++;
if (hpux_check_patch(app:"CDE.CDE-ENG-A-MSG", version:"B.11.04")) flag++;
if (hpux_check_patch(app:"CDE.CDE-FONTS", version:"B.11.04")) flag++;
if (hpux_check_patch(app:"CDE.CDE-HELP-RUN", version:"B.11.04")) flag++;
if (hpux_check_patch(app:"CDE.CDE-MIN", version:"B.11.04")) flag++;
if (hpux_check_patch(app:"CDE.CDE-RUN", version:"B.11.04")) flag++;
if (hpux_check_patch(app:"CDE.CDE-SHLIBS", version:"B.11.04")) flag++;
if (hpux_check_patch(app:"CDE.CDE-TT", version:"B.11.04")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
