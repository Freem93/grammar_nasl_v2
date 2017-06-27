#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHNE_24715. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(16895);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2013/04/20 00:32:52 $");

  script_xref(name:"HP", value:"HPSBUX0309");
  script_xref(name:"HP", value:"SSRT3637");

  script_name(english:"HP-UX PHNE_24715 : HPSBUX0309-283 SSRT3637 Potential Security Vulnerability in socket programs");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.00 cumulative ARPA Transport patch : 

Potential Security Vulnerability in socket programs."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHNE_24715 or subsequent."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/09/29");
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
  exit(0, "The host is not affected since PHNE_24715 applies to a different OS release.");
}

patches = make_list("PHNE_24715", "PHNE_25423", "PHNE_26771", "PHNE_27886", "PHNE_28538", "PHNE_29473", "PHNE_32041", "PHNE_33395", "PHNE_35729");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"Networking.NET-KRN", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"Networking.NET-PRG", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"Networking.NET-RUN", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"Networking.NET2-KRN", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"Networking.NMS2-KRN", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"OS-Core.CORE2-KRN", version:"B.11.00")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
