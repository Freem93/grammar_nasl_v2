#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_22540. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(16824);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/04/20 00:36:50 $");

  script_xref(name:"HP", value:"emr_na-c00993861");
  script_xref(name:"HP", value:"HPSBUX00129");
  script_xref(name:"HP", value:"SSRT071374");

  script_name(english:"HP-UX PHSS_22540 : HP-UX MC/ServiceGuard, Local Denial of Service (DoS) (HPSBUX00129 SSRT071374 rev.2)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.X MC/ServiceGuard and SG-OPS Edition A.11.09 : 

MC/ServiceGuard file and directory permissions are incorrect."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00993861
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?008ac708"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_22540 or subsequent."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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

if (!hpux_check_ctx(ctx:"11.00 11.11"))
{
  exit(0, "The host is not affected since PHSS_22540 applies to a different OS release.");
}

patches = make_list("PHSS_22540", "PHSS_22683", "PHSS_22876", "PHSS_23511", "PHSS_24033", "PHSS_24536", "PHSS_24850", "PHSS_25499", "PHSS_25935", "PHSS_26338", "PHSS_26750", "PHSS_27158");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"ATS-CORE.ATS-RUN", version:"A.11.09")) flag++;
if (hpux_check_patch(app:"CM-Provider-MOF.CM-MOF", version:"A.11.09")) flag++;
if (hpux_check_patch(app:"CM-Provider-MOF.CM-PROVIDER", version:"A.11.09")) flag++;
if (hpux_check_patch(app:"Cluster-Monitor.CM-CORE", version:"A.11.09")) flag++;
if (hpux_check_patch(app:"DLM-Clust-Mon.CM-CORE", version:"A.11.09")) flag++;
if (hpux_check_patch(app:"DLM-Pkg-Mgr.CM-PKG", version:"A.11.09")) flag++;
if (hpux_check_patch(app:"DLM.CM-DLM", version:"A.11.09")) flag++;
if (hpux_check_patch(app:"DLM.CM-DLM-CMDS", version:"A.11.09")) flag++;
if (hpux_check_patch(app:"Package-Manager.CM-PKG", version:"A.11.09")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
