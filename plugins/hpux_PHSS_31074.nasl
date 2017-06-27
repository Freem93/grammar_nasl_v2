#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_31074. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(17550);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/04/20 00:41:03 $");

  script_cve_id("CVE-2004-1486");
  script_xref(name:"HP", value:"emr_na-c00901843");
  script_xref(name:"HP", value:"HPSBUX01080");
  script_xref(name:"HP", value:"SSRT3526");

  script_name(english:"HP-UX PHSS_31074 : HP-UX Running Serviceguard, Remote Increase in Privilege (HPSBUX01080 SSRT3526 rev.2)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.23 COM B.03.00.00/COM B.03.00.01 : 

A potential security vulnerability has been identified with HP
Serviceguard running on HP-UX and Linux that may allow remote
unauthorized privileges."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00901843
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?88e3e589"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_31074 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/18");
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

if (!hpux_check_ctx(ctx:"11.23"))
{
  exit(0, "The host is not affected since PHSS_31074 applies to a different OS release.");
}

patches = make_list("PHSS_31074", "PHSS_31078", "PHSS_32741", "PHSS_33040");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"CM-Provider-MOF.CM-PROVIDER", version:"B.03.00.00")) flag++;
if (hpux_check_patch(app:"CM-Provider-MOF.CM-PROVIDER", version:"B.03.00.01")) flag++;
if (hpux_check_patch(app:"Cluster-OM.CM-OM", version:"B.03.00.00")) flag++;
if (hpux_check_patch(app:"Cluster-OM.CM-OM", version:"B.03.00.01")) flag++;
if (hpux_check_patch(app:"Cluster-OM.CM-OM-AUTH", version:"B.03.00.00")) flag++;
if (hpux_check_patch(app:"Cluster-OM.CM-OM-AUTH", version:"B.03.00.01")) flag++;
if (hpux_check_patch(app:"Cluster-OM.CM-OM-TOOLS", version:"B.03.00.00")) flag++;
if (hpux_check_patch(app:"Cluster-OM.CM-OM-TOOLS", version:"B.03.00.01")) flag++;
if (hpux_check_patch(app:"OPS-Provider-MOF.OPS-PROVIDER", version:"B.03.00.00")) flag++;
if (hpux_check_patch(app:"OPS-Provider-MOF.OPS-PROVIDER", version:"B.03.00.01")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
