#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHKL_23628. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(16721);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/04/20 00:32:52 $");

  script_xref(name:"HP", value:"emr_na-c00968563");
  script_xref(name:"HP", value:"HPSBUX00156");
  script_xref(name:"HP", value:"SSRT071363");

  script_name(english:"HP-UX PHKL_23628 : HP-UX Running setrlimit(1M), Denial of Service (DoS) (HPSBUX00156 SSRT071363 rev.3)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.00 probe,sysproc,shmem,thread cumulative patch : 

The setrlimit() allows incorrect core files Rev.1 **."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00968563
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a86d1269"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHKL_23628 or subsequent."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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

if (!hpux_check_ctx(ctx:"11.00"))
{
  exit(0, "The host is not affected since PHKL_23628 applies to a different OS release.");
}

patches = make_list("PHKL_23628", "PHKL_23812", "PHKL_23813", "PHKL_23857", "PHKL_24015", "PHKL_24116", "PHKL_24273", "PHKL_24457", "PHKL_24612", "PHKL_24826", "PHKL_24971", "PHKL_25164", "PHKL_25188", "PHKL_25210", "PHKL_25525", "PHKL_25906", "PHKL_26800", "PHKL_27157", "PHKL_27238", "PHKL_27364", "PHKL_27759", "PHKL_27919", "PHKL_27994", "PHKL_28053", "PHKL_28180", "PHKL_28766", "PHKL_29345", "PHKL_29648", "PHKL_30190", "PHKL_30709", "PHKL_31867", "PHKL_33500", "PHKL_33819", "PHKL_34341");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"OS-Core.CORE-KRN", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"OS-Core.CORE2-KRN", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"ProgSupport.C-INC", version:"B.11.00")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
