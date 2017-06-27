#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_38009. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(33190);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2013/04/20 00:44:14 $");

  script_cve_id("CVE-2008-1842");
  script_xref(name:"HP", value:"emr_na-c01471755");
  script_xref(name:"HP", value:"SSRT080024");
  script_xref(name:"HP", value:"SSRT080041");

  script_name(english:"HP-UX PHSS_38009 : HP OpenView Network Node Manager (OV NNM), Remote Execution of Arbitrary Code, Denial of Service (DoS) (HPSBMA02340 SSRT080024, SSRT080041 rev.1)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.X OV NNM8.01 NNM 8.0x Patch 8.02.001 : 

A potential vulnerability has been identified with HP OpenView Network
Node Manager (OV NNM). The vulnerability could be exploited remotely
execute arbitrary code or to create a Denial of Service (DoS)."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01471755
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2ccf6292"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_38009 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2013 Tenable Network Security, Inc.");
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

if (!hpux_check_ctx(ctx:"11.23 11.31"))
{
  exit(0, "The host is not affected since PHSS_38009 applies to a different OS release.");
}

patches = make_list("PHSS_38009", "PHSS_38435", "PHSS_38609");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"HPOvNNM.HPNMSCOMPS", version:"2.02.050")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNMSCAUSESV", version:"2.02.070")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNMSCOMMON", version:"2.02.070")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNMSDISCOSV", version:"2.02.070")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNMSEMBDDB", version:"2.02.074")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNMSEVNT", version:"2.02.073")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNMSEVTPSV", version:"2.02.070")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNMSLIC", version:"2.02.070")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNMSSNMPCO", version:"2.02.070")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNMSSPMD", version:"2.02.074")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNNMGEN", version:"2.02.070")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNNMINSTALL", version:"2.02.070")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVNNMUI", version:"2.02.070")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVSNMP", version:"2.02.074")) flag++;
if (hpux_check_patch(app:"HPOvNNM.HPOVSTPLR", version:"2.02.070")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
