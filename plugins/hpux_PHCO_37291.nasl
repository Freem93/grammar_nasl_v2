#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHCO_37291. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(32453);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2014/03/12 15:37:24 $");

  script_cve_id("CVE-2008-1660");
  script_osvdb_id(45362);
  script_xref(name:"HP", value:"emr_na-c01455884");
  script_xref(name:"HP", value:"HPSBUX02335");
  script_xref(name:"HP", value:"SSRT071454");

  script_name(english:"HP-UX PHCO_37291 : HP-UX Running useradd(1M), Local Unauthorized Access (HPSBUX02335 SSRT071454 rev.2)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.23 ugm cumulative patch : 

A potential security vulnerability has been identified HP-UX running
the useradd(1M) command. The vulnerability could be exploited locally
to allow unauthorized access to directories or files."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01455884
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?507b3f40"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHCO_37291 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/21");
  script_set_attribute(attribute:"patch_modification_date", value:"2008/05/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/28");
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
  exit(0, "The host is not affected since PHCO_37291 applies to a different OS release.");
}

patches = make_list("PHCO_37291", "PHCO_38491", "PHCO_43189");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"OS-Core.ADMN-ENG-A-MAN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"OS-Core.SYS-ADMIN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"OS-Core.SYS2-ADMIN", version:"B.11.23")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:hpux_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
