#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_32966. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(22179);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2014/03/12 15:37:25 $");

  script_cve_id("CVE-2005-2495");
  script_osvdb_id(19352);
  script_xref(name:"HP", value:"emr_na-c00732238");
  script_xref(name:"HP", value:"HPSBUX02137");
  script_xref(name:"HP", value:"SSRT051024");

  script_name(english:"HP-UX PHSS_32966 : HP-UX Running Xserver Local Execution of Arbitrary Code, Privilege Elevation (HPSBUX02137 SSRT051024 rev.1)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.11 Xserver cumulative patch : 

A potential security vulnerability has been identified in the Xserver
running on HP-UX. The vulnerability could be exploited by a local user
to execute arbitrary code with the privileges of the Xserver."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00732238
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6e99a9a6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_32966 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/08/08");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");
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
  exit(0, "The host is not affected since PHSS_32966 applies to a different OS release.");
}

patches = make_list("PHSS_32966", "PHSS_32971", "PHSS_32976", "PHSS_32977", "PHSS_34385", "PHSS_34389", "PHSS_34390", "PHSS_34391", "PHSS_34392");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"Xserver.AGRM", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"Xserver.DDX-ADVANCED", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"Xserver.DDX-ENTRY", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"Xserver.DDX-LOAD", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"Xserver.DDX-SAM", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"Xserver.DDX-SLS", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"Xserver.DDX-UTILS", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"Xserver.X11-SERV", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"Xserver.X11-SERV-MAN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"Xserver.XEXT-DBE", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"Xserver.XEXT-DBE-MAN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"Xserver.XEXT-DPMS", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"Xserver.XEXT-DPMS-MAN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"Xserver.XEXT-HPCR", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"Xserver.XEXT-HPCR-MAN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"Xserver.XEXT-MBX", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"Xserver.XEXT-RECORD", version:"B.11.11")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:hpux_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
