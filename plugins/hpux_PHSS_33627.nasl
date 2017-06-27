#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_33627. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(20085);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2014/03/12 15:42:17 $");

  script_cve_id("CVE-2005-1974");
  script_osvdb_id(17340);
  script_xref(name:"HP", value:"emr_na-c01033698");
  script_xref(name:"HP", value:"SSRT051052");

  script_name(english:"HP-UX PHSS_33627 : HP OpenView Operations and OpenView VantagePoint Java Runtime Environment (JRE), Remote Privileged Access (HPSBMA01234 SSRT051052 rev.2)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.X OV OVO8.1X PARISC JavaGUI client A.08.14 : 

A potential security vulnerability has been identified with the HP
OpenView Operations and OpenView VantagePoint Java Runtime Environment
(JRE). This vulnerability may allow an untrusted remote applet to
elevate its privileges."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01033698
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?43a5c3bd"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_33627 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/25");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/13");
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

if (!hpux_check_ctx(ctx:"11.00 11.11 11.23"))
{
  exit(0, "The host is not affected since PHSS_33627 applies to a different OS release.");
}

patches = make_list("PHSS_33627", "PHSS_33864", "PHSS_34363", "PHSS_34733", "PHSS_35228", "PHSS_35791", "PHSS_36273", "PHSS_36772", "PHSS_37183", "PHSS_37566", "PHSS_38203", "PHSS_38854", "PHSS_39327", "PHSS_39896", "PHSS_40468", "PHSS_41213");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"OVOPC-WWW.OVOPC-WWW-ENG", version:"A.08.10.160")) flag++;
if (hpux_check_patch(app:"OVOPC-WWW.OVOPC-WWW-GUI", version:"A.08.10.160")) flag++;
if (hpux_check_patch(app:"OVOPC-WWW.OVOPC-WWW-JPN", version:"A.08.10.160")) flag++;
if (hpux_check_patch(app:"OVOPC-WWW.OVOPC-WWW-KOR", version:"A.08.10.160")) flag++;
if (hpux_check_patch(app:"OVOPC-WWW.OVOPC-WWW-SCH", version:"A.08.10.160")) flag++;
if (hpux_check_patch(app:"OVOPC-WWW.OVOPC-WWW-SPA", version:"A.08.10.160")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:hpux_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
