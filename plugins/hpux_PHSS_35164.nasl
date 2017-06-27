#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_35164. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(26146);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/04/20 00:41:04 $");

  script_cve_id("CVE-2007-0866");
  script_xref(name:"HP", value:"emr_na-c00862204");
  script_xref(name:"HP", value:"SSRT071300");

  script_name(english:"HP-UX PHSS_35164 : HP OpenView Storage Data Protector, Local Execution of Arbitrary Code (HPSBMA02190 SSRT071300 rev.1)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.X OV DP5.50 PA-RISC patch - DA packet : 

A potential security vulnerability has been identified with HP
OpenView Storage Data Protector running on HP-UX with PHSS_35149 or
PHSS_35150 installed and Solaris with DPSOL_00229 installed. The
vulnerability could be exploited by a local user to execute arbitrary
code."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00862204
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?df4eec13"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_35164 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
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

if (!hpux_check_ctx(ctx:"11.00 11.11 11.23", proc:"parisc"))
{
  exit(0, "The host is not affected since PHSS_35164 applies to a different OS release / architecture.");
}

patches = make_list("PHSS_35164", "PHSS_36292", "PHSS_38284");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"DATA-PROTECTOR.OMNI-CORE-IS", version:"A.05.50")) flag++;
if (hpux_check_patch(app:"DATA-PROTECTOR.OMNI-HPUX-P", version:"A.05.50")) flag++;
if (hpux_check_patch(app:"DATA-PROTECTOR.OMNI-OTHUX-P", version:"A.05.50")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:hpux_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
