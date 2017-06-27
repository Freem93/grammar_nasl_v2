#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_33130. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(21657);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/02/03 14:36:53 $");

  script_cve_id("CVE-2004-0687", "CVE-2004-0688");
  script_osvdb_id(10026, 10027, 10028, 10029, 10030, 10031, 10032, 10033, 10034);
  script_xref(name:"CERT", value:"537878");
  script_xref(name:"CERT", value:"882750");
  script_xref(name:"HP", value:"emr_na-c00600177");
  script_xref(name:"HP", value:"HPSBUX02119");
  script_xref(name:"HP", value:"SSRT4848");

  script_name(english:"HP-UX PHSS_33130 : HP-UX Running Motif Applications Remote Arbitrary Code Execution, Denial of Service (DoS) (HPSBUX02119 SSRT4848 rev.1)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.11 X/Motif Runtime Periodic Patch : 

Potential security vulnerabilities have been identified with Motif
applications running on HP-UX. The potential vulnerabilities could be
exploited to allow remote execution of arbitrary code or Denial for
Service (DoS). References: CERT VU#537878, VU#882750."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00600177
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7b697647"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_33130 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/06/06");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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
  exit(0, "The host is not affected since PHSS_33130 applies to a different OS release.");
}

patches = make_list("PHSS_33130", "PHSS_35711", "PHSS_37028", "PHSS_44188");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"X11.MOTIF-SHLIB", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"X11.X11-FONT-AUX", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"X11.X11-FONT-MIN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"X11.X11-TCH-B-MSG", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"X11.X11R5-SHLIBS", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"X11.X11R6-SHLIBS", version:"B.11.11")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
