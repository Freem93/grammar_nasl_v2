#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHCO_38273. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(33863);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2014/03/12 16:06:24 $");

  script_cve_id("CVE-2008-1664");
  script_osvdb_id(47376);
  script_xref(name:"HP", value:"emr_na-c01520421");
  script_xref(name:"IAVT", value:"2008-T-0041");
  script_xref(name:"HP", value:"HPSBUX02355");
  script_xref(name:"HP", value:"SSRT080023");

  script_name(english:"HP-UX PHCO_38273 : HP-UX Using libc, Remote Denial of Service (DoS) (HPSBUX02355 SSRT080023 rev.2)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.23 libc cumulative patch : 

A potential security vulnerability has been identified in HP-UX using
libc. This vulnerability could be exploited remotely to create a
Denial of Service (DoS)."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01520421
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?53753826"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHCO_38273 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/01");
  script_set_attribute(attribute:"patch_modification_date", value:"2009/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/12");
  script_set_attribute(attribute:"stig_severity", value:"II");
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

if (!hpux_check_ctx(ctx:"11.23"))
{
  exit(0, "The host is not affected since PHCO_38273 applies to a different OS release.");
}

patches = make_list("PHCO_38273", "PHCO_38637", "PHCO_40571", "PHCO_42273");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"OS-Core.C-MIN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"OS-Core.C-MIN-64ALIB", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"OS-Core.CORE2-64SLIB", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"OS-Core.CORE2-SHLIBS", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"ProgSupport.PROG-AX-64ALIB", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"ProgSupport.PROG-MIN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"ProgSupport.PROG2-AUX", version:"B.11.23")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
