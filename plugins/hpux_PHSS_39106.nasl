#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_39106. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(44350);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2014/03/12 15:42:19 $");

  script_cve_id("CVE-2009-4183");
  script_osvdb_id(61955);
  script_xref(name:"HP", value:"emr_na-c01992642");
  script_xref(name:"HP", value:"SSRT090171");

  script_name(english:"HP-UX PHSS_39106 : HP OpenView Storage Data Protector, Local Unauthorized Access (HPSBMA02502 SSRT090171 rev.1)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.X OV DP6.00 HP-UX IA64 - Cell Server patch : 

A potential security vulnerability has been identified with HP
OpenView Storage Data Protector. The vulnerability could be exploited
to gain unauthorized access."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01992642
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cadb15ff"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_39106 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/02");
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

if (!hpux_check_ctx(ctx:"11.23 11.31", proc:"ia64"))
{
  exit(0, "The host is not affected since PHSS_39106 applies to a different OS release / architecture.");
}

patches = make_list("PHSS_39106", "PHSS_39794", "PHSS_40171", "PHSS_40567", "PHSS_41264", "PHSS_41869");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"DATA-PROTECTOR.OMNI-CS", version:"A.06.00")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:hpux_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
