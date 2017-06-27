#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_34887. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(23628);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2014/03/12 15:42:18 $");

  script_cve_id("CVE-2006-2579", "CVE-2006-4201");
  script_osvdb_id(25869, 27943);
  script_xref(name:"HP", value:"emr_na-c00671912");
  script_xref(name:"HP", value:"emr_na-c00742778");
  script_xref(name:"HP", value:"SSRT061157");
  script_xref(name:"HP", value:"SSRT061184");

  script_name(english:"HP-UX PHSS_34887 : s700_800 11.X OV DP5.10 patch - CORE packet");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.X OV DP5.10 patch - CORE packet : 

The remote HP-UX host is affected by multiple vulnerabilities :

  - A potential security vulnerability has been identified
    with HP OpenView Storage Data Protector running on
    HP-UX, IBM AIX, Linux, Microsoft Windows, and Solaris.
    This vulnerability could allow a remote unauthorized
    user to execute arbitrary commands. References: NISCC
    412866. (HPSBMA02138 SSRT061184)

  - A potential security vulnerability has been identified
    with HP OpenView Storage Data Protector running on
    HP-UX, IBM AIX, Linux, Microsoft Windows, and Solaris.
    This vulnerability could allow a remote unauthorized
    user to execute arbitrary commands. (HPSBMA02121
    SSRT061157)"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00671912
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?abebabf7"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00742778
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?38669b29"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_34887 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/10/23");
  script_set_attribute(attribute:"patch_modification_date", value:"2006/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/11/07");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/23");
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

if (!hpux_check_ctx(ctx:"11.00 11.11 11.23"))
{
  exit(0, "The host is not affected since PHSS_34887 applies to a different OS release.");
}

patches = make_list("PHSS_34887", "PHSS_36431");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"DATA-PROTECTOR.OMNI-CORE-IS", version:"A.05.10")) flag++;
if (hpux_check_patch(app:"DATA-PROTECTOR.OMNI-FRA-LS-P", version:"A.05.10")) flag++;
if (hpux_check_patch(app:"DATA-PROTECTOR.OMNI-INTEG-P", version:"A.05.10")) flag++;
if (hpux_check_patch(app:"DATA-PROTECTOR.OMNI-JPN-LS-P", version:"A.05.10")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
