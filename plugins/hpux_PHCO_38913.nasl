#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHCO_38913. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(36056);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/04/18 15:25:37 $");

  script_cve_id("CVE-2009-0207");
  script_xref(name:"HP", value:"emr_na-c01674733");
  script_xref(name:"HP", value:"HPSBUX02409");
  script_xref(name:"HP", value:"SSRT080171");

  script_name(english:"HP-UX PHCO_38913 : HP-UX Running VERITAS File System (VRTSvxfs) or VERITAS Oracle Disk Manager (VRTSodm), Local Escalation of Privilege (HPSBUX02409 SSRT080171 rev.3)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.31 VRTS 5.0 GARP3 VRTSfsman Command Patch : 

A potential security vulnerability has been identified with HP-UX
running VRTSvxfs and VRTSodm. The vulnerability could be exploited
locally to cause an escalation of privilege. VRTSvxfs and VRTSodm are
bundled with Storage Management Suite (SMS) and Storage Management for
Oracle (SMO)."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01674733
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6f594e69"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHCO_38913 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/19");
  script_set_attribute(attribute:"patch_modification_date", value:"2009/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/03/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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

if (!hpux_check_ctx(ctx:"11.31"))
{
  exit(0, "The host is not affected since PHCO_38913 applies to a different OS release.");
}

patches = make_list("PHCO_38913", "PHCO_40290", "PHCO_41297", "PHCO_42236", "PHCO_42917", "PHCO_43501", "PHCO_43686", "PHCO_44462");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"VRTSfsman.VXFS-ENG-A-MAN", version:"5.0.31.0")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:hpux_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
