#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_40229. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(44404);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2014/03/12 15:42:19 $");

  script_cve_id("CVE-2009-4184");
  script_osvdb_id(62070);
  script_xref(name:"HP", value:"emr_na-c01894850");
  script_xref(name:"HP", value:"HPSBUX02464");
  script_xref(name:"HP", value:"SSRT090210");

  script_name(english:"HP-UX PHSS_40229 : HP Enterprise Cluster Master Toolkit (ECMT) running on HP-UX, Local Unauthorized Access (HPSBUX02464 SSRT090210 rev.1)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.23 ECMT B.05.00 patch : 

A potential security vulnerability has been identified on HP
Enterprise Cluster Master Toolkit (ECMT) version B.05.00 running on
HP-UX. This vulnerability could be exploited by local users to gain
unauthorized access."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01894850
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8ab4ead7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_40229 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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
  exit(0, "The host is not affected since PHSS_40229 applies to a different OS release.");
}

patches = make_list("PHSS_40229", "PHSS_40791", "PHSS_40986", "PHSS_41315");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"SG-Oracle-Tool.CM-ORACLE", version:"B.05.00")) flag++;
if (hpux_check_patch(app:"SG-Sybase-Tool.CM-SYBASE", version:"B.05.00")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:hpux_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
