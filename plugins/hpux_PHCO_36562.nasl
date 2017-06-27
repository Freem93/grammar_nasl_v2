#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHCO_36562. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(33828);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2014/03/12 16:06:24 $");

  script_cve_id("CVE-2008-1662");
  script_osvdb_id(47273);
  script_xref(name:"HP", value:"emr_na-c01367453");
  script_xref(name:"IAVT", value:"2008-T-0042");
  script_xref(name:"HP", value:"HPSBUX02286");
  script_xref(name:"HP", value:"SSRT071466");

  script_name(english:"HP-UX PHCO_36562 : HP-UX Running System Administration Manager (SAM), Unintended Remote Access (HPSBUX02286 SSRT071466 rev.1)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.11 cumulative SAM patch : 

A potential security vulnerability has been identified in HP-UX
running System Administration Manager (SAM). This vulnerability may
allow unintended remote access."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01367453
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8bfeebd2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHCO_36562 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(16);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/05");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2014 Tenable Network Security, Inc.");
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
  exit(0, "The host is not affected since PHCO_36562 applies to a different OS release.");
}

patches = make_list("PHCO_36562");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"InternetSrvcs.INETSVCS-BOOT", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"OS-Core.UX-CORE", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"SystemAdmin.SAM", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"SystemAdmin.SAM-ENG-A-MAN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"SystemAdmin.SAM-HELP", version:"B.11.11")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
