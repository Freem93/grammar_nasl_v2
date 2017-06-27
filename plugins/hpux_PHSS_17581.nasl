#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_17581. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(17446);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2014/03/12 15:37:25 $");

  script_cve_id("CVE-1999-0435");
  script_osvdb_id(5971, 6115);
  script_xref(name:"HP", value:"HPSBUX9903-096");

  script_name(english:"HP-UX PHSS_17581 : s700_800 11.00 MC ServiceGuard 11.05 Cumulative Patch");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.00 MC ServiceGuard 11.05 Cumulative Patch : 

MC/ServiceGuard and MC/LockManager exhibit improper implementation of
restricted SAM functionality."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_17581 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"1999/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/18");
  script_set_attribute(attribute:"vuln_publication_date", value:"1999/03/30");
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

if (!hpux_check_ctx(ctx:"11.00"))
{
  exit(0, "The host is not affected since PHSS_17581 applies to a different OS release.");
}

patches = make_list("PHSS_17581");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"ATS-CORE-Jpn.J-ATS-RUN", version:"A.11.05")) flag++;
if (hpux_check_patch(app:"ATS-CORE.ATS-RUN", version:"A.11.05")) flag++;
if (hpux_check_patch(app:"Cluster-Mon-Jpn.J-CM-CORE", version:"A.11.05")) flag++;
if (hpux_check_patch(app:"Cluster-Monitor.CM-CORE", version:"A.11.05")) flag++;
if (hpux_check_patch(app:"Package-Manager.CM-PKG", version:"A.11.05")) flag++;
if (hpux_check_patch(app:"Package-Mgr-Jpn.J-CM-PKG", version:"A.11.05")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
