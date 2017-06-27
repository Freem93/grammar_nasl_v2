#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHNE_20371. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(16554);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/04/20 00:32:52 $");

  script_xref(name:"HP", value:"HPSBUX9910");

  script_name(english:"HP-UX PHNE_20371 : HPSBUX9910-104 Sec. Vulnerability regarding automountd (rev. 02)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.0 ONC cumulative patch : 

automountd can run user programs as root."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHNE_20371 or subsequent."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2000/05/02");
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
  exit(0, "The host is not affected since PHNE_20371 applies to a different OS release.");
}

patches = make_list("PHNE_20371", "PHNE_21376", "PHNE_22125", "PHNE_22642", "PHNE_23249", "PHNE_23833", "PHNE_24034", "PHNE_24909", "PHNE_25484", "PHNE_25626", "PHNE_26387", "PHNE_27217", "PHNE_28102", "PHNE_28567", "PHNE_28982", "PHNE_29210", "PHNE_29302", "PHNE_29785", "PHNE_29882", "PHNE_30377", "PHNE_30660", "PHNE_31096");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"InternetSrvcs.INETSVCS-INETD", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"NFS.KEY-CORE", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"NFS.NFS-64ALIB", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"NFS.NFS-64SLIB", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"NFS.NFS-CLIENT", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"NFS.NFS-CORE", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"NFS.NFS-ENG-A-MAN", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"NFS.NFS-KRN", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"NFS.NFS-PRG", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"NFS.NFS-SERVER", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"NFS.NFS-SHLIBS", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"NFS.NIS-CLIENT", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"NFS.NIS-CORE", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"NFS.NIS-SERVER", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"NFS.NISPLUS-CORE", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"OS-Core.CORE-ENG-A-MAN", version:"B.11.00")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
