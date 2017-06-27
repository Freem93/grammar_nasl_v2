#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_42253. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(56848);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2014/03/12 16:06:50 $");

  script_cve_id("CVE-2011-2398");
  script_bugtraq_id(48577);
  script_osvdb_id(73616);
  script_xref(name:"HP", value:"emr_na-c02904002");
  script_xref(name:"IAVB", value:"2011-B-0079");
  script_xref(name:"HP", value:"HPSBUX02688");
  script_xref(name:"HP", value:"SSRT100513");

  script_name(english:"HP-UX PHSS_42253 : HP-UX Dynamic Loader, Local Privilege Escalation, Denial of Service (DoS) (HPSBUX02688 SSRT100513 rev.1)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.11 ld(1) and linker tools cumulative patch : 

A potential security vulnerability has been identified in HP-UX
dynamic loader. The vulnerability could be exploited locally to create
a privilege escalation, or a Denial of Service (DoS)."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02904002
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9bc129ed"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_42253 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/06");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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

if (!hpux_check_ctx(ctx:"11.11"))
{
  exit(0, "The host is not affected since PHSS_42253 applies to a different OS release.");
}

patches = make_list("PHSS_42253", "PHSS_42977");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"OS-Core.C-KRN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"OS-Core.C-MIN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"OS-Core.C-MIN-64ALIB", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"OS-Core.CAUX-ENG-A-MAN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"OS-Core.CMDS-AUX", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"OS-Core.CORE-64SLIB", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"OS-Core.CORE-SHLIBS", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"OS-Core.LINKER-HELP", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"OS-Core.UX-FRE-I-MSG", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"OS-Core.UX-FRE-U-MSG", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"OS-Core.UX-GER-I-MSG", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"OS-Core.UX-GER-U-MSG", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"OS-Core.UX-ITA-I-MSG", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"OS-Core.UX-ITA-U-MSG", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"OS-Core.UX-JPN-E-MSG", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"OS-Core.UX-JPN-S-MSG", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"OS-Core.UX-JPN-U-MSG", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"OS-Core.UX-KOR-E-MSG", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"OS-Core.UX-KOR-U-MSG", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"OS-Core.UX-SCH-H-MSG", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"OS-Core.UX-SCH-U-MSG", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"OS-Core.UX-SPA-I-MSG", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"OS-Core.UX-SPA-U-MSG", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"OS-Core.UX-TCH-B-MSG", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"OS-Core.UX-TCH-E-MSG", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"OS-Core.UX-TCH-U-MSG", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"ProgSupport.C-ENG-A-MAN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"ProgSupport.C-INC", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"ProgSupport.LANG-MIN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"ProgSupport.PAUX-ENG-A-MAN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"ProgSupport.PROG-AUX", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"ProgSupport.PROG-AX-64ALIB", version:"B.11.11")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:hpux_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
