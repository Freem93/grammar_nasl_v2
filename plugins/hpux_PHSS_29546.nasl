#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_29546. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(17502);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/04/20 00:41:02 $");

  script_xref(name:"CERT", value:"379828");
  script_xref(name:"HP", value:"HPSBUX0310");
  script_xref(name:"HP", value:"SSRT3642");

  script_name(english:"HP-UX PHSS_29546 : HPSBUX0310-285 SSRT3642 Potential Security Vulnerabilities Apache web server HP-UX VVOS and Webproxy.");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.04 Virtualvault 4.6 OWS update : 

1. Potential Apache web server crash when it goes into an infinite
loop due to too many subsequent internal redirects and nested
subrequests. (VU#379828) 2. No de-allocation of file descriptors while
servicing CGI scripts through child processes."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_29546 or subsequent."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/18");
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

if (!hpux_check_ctx(ctx:"11.04"))
{
  exit(0, "The host is not affected since PHSS_29546 applies to a different OS release.");
}

patches = make_list("PHSS_29546", "PHSS_29691", "PHSS_30154", "PHSS_30405", "PHSS_30645", "PHSS_30947", "PHSS_31057", "PHSS_31826", "PHSS_32183", "PHSS_33397", "PHSS_34120", "PHSS_35108", "PHSS_35462", "PHSS_35557");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"VaultTS.VV-CORE-CMN", version:"A.04.60")) flag++;
if (hpux_check_patch(app:"VaultTS.VV-IWS-GUI", version:"A.04.60")) flag++;
if (hpux_check_patch(app:"VaultTS.VV-IWS-JAVA", version:"A.04.60")) flag++;
if (hpux_check_patch(app:"VaultWS.WS-CORE", version:"A.04.60")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
