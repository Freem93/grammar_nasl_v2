#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_29964. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(16586);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2014/03/12 15:37:25 $");

  script_cve_id("CVE-2006-1389");
  script_osvdb_id(24097);
  script_xref(name:"HP", value:"emr_na-c00622788");
  script_xref(name:"HP", value:"emr_na-c00906162");
  script_xref(name:"HP", value:"emr_na-c00958403");
  script_xref(name:"HP", value:"HPSBUX00276");
  script_xref(name:"HP", value:"HPSBUX00299");
  script_xref(name:"HP", value:"HPSBUX02105");
  script_xref(name:"HP", value:"SSRT061134");
  script_xref(name:"HP", value:"SSRT3620");
  script_xref(name:"HP", value:"SSRT3660");

  script_name(english:"HP-UX PHSS_29964 : s700_800 11.11 HP DCE/9000 1.8 DCE Client IPv6 patch");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.11 HP DCE/9000 1.8 DCE Client IPv6 patch : 

The remote HP-UX host is affected by multiple vulnerabilities :

  - Potential security vulnerability in B.11.11 DCE.
    (HPSBUX00276 SSRT3620)

  - A potential security vulnerability has been identified
    in HP-UX running swagentd. The vulnerability could be
    exploited remotely by an unauthenticated user to cause
    swagentd to abort resulting in a Denial of Service
    (DoS). References: HPSBUX0311-299 SSRT3660. (HPSBUX02105
    SSRT061134)

  - Potential security vulnerability in DCE. (HPSBUX00299
    SSRT3660)"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00958403
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?be4e8703"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00906162
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d4f37774"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00622788
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e92e3fa2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_29964 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/11/17");
  script_set_attribute(attribute:"patch_modification_date", value:"2006/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/16");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/03/24");
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

if (!hpux_check_ctx(ctx:"11.11"))
{
  exit(0, "The host is not affected since PHSS_29964 applies to a different OS release.");
}

patches = make_list("PHSS_29964", "PHSS_33949", "PHSS_35467", "PHSS_36004", "PHSS_38183", "PHSS_42852");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"DCE-Core.DCE-COR-64SLIB", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"DCE-Core.DCE-CORE-DTS", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"DCE-Core.DCE-CORE-RUN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"DCE-Core.DCE-CORE-SHLIB", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"DCE-Core.DCEC-ENG-A-MAN", version:"B.11.11")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
