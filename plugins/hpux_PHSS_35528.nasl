#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_35528. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(38968);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2015/04/21 13:25:43 $");

  script_cve_id("CVE-2007-5946");
  script_osvdb_id(42232);
  script_xref(name:"HP", value:"emr_na-c01241483");
  script_xref(name:"HP", value:"HPSBUX02285");
  script_xref(name:"HP", value:"SSRT071484");

  script_name(english:"HP-UX PHSS_35528 : HP-UX Running Aries PA Emulator, Local Unauthorized Access (HPSBUX02285 SSRT071484 rev.1)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.23 Aries cumulative patch : 

A potential security vulnerability has been identified in the Aries
PA-RISC emulation software running on HP-UX IA-64 platforms only. This
vulnerability may allow local unauthorized access."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01241483
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6e183281"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_35528 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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

if (!hpux_check_ctx(ctx:"11.23", proc:"ia64"))
{
  exit(0, "The host is not affected since PHSS_35528 applies to a different OS release / architecture.");
}

patches = make_list("PHSS_35528", "PHSS_36519", "PHSS_37552", "PHSS_38526", "PHSS_39293", "PHSS_39897", "PHSS_41098", "PHSS_41422", "PHSS_42738", "PHSS_42862", "PHSS_43149", "PHSS_44257");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"OS-Core.CORE2-64SLIB", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"OS-Core.CORE2-SHLIBS", version:"B.11.23")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
