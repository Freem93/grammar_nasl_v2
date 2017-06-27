#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHCO_34764. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(22329);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2014/03/12 15:37:23 $");

  script_cve_id("CVE-2006-1248");
  script_osvdb_id(23997);
  script_xref(name:"HP", value:"emr_na-c00614838");
  script_xref(name:"HP", value:"HPSBUX02102");
  script_xref(name:"HP", value:"SSRT051078");

  script_name(english:"HP-UX PHCO_34764 : HP-UX usermod(1M) Local Unauthorized Access. (HPSBUX02102 SSRT051078 rev.4)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.23 ugm cumulative patch : 

A vulnerability has been identified with certain versions of the HP-UX
usermod(1M) command. A certain combination of options can result in
recursively changing the ownership of all directories and files under
a user's new home directory. This may result in unauthorized access to
these directories and files."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00614838
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?db51d206"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHCO_34764 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/18");
  script_set_attribute(attribute:"patch_modification_date", value:"2006/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/09/12");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/03/13");
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

if (!hpux_check_ctx(ctx:"11.23"))
{
  exit(0, "The host is not affected since PHCO_34764 applies to a different OS release.");
}

patches = make_list("PHCO_34764", "PHCO_35874", "PHCO_36239", "PHCO_37178", "PHCO_37291", "PHCO_38491", "PHCO_43189");
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
