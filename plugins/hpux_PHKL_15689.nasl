#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHKL_15689. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(17391);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2014/03/12 15:37:24 $");

  script_cve_id("CVE-1999-0353");
  script_osvdb_id(6792);
  script_xref(name:"HP", value:"HPSBUX9902-091");

  script_name(english:"HP-UX PHKL_15689 : s700_800 11.0 AutoFS support patch");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.0 AutoFS support patch : 

rpc.pcnfsd has an error in its use of the spool directory."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHKL_15689 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"1998/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/18");
  script_set_attribute(attribute:"vuln_publication_date", value:"1999/02/08");
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
  exit(0, "The host is not affected since PHKL_15689 applies to a different OS release.");
}

patches = make_list("PHKL_15689", "PHKL_20315", "PHKL_21361", "PHKL_21608", "PHKL_22142", "PHKL_22517", "PHKL_22589", "PHKL_24734", "PHKL_24753", "PHKL_24943", "PHKL_25475", "PHKL_25999", "PHKL_26059", "PHKL_27089", "PHKL_27351", "PHKL_27510", "PHKL_27770", "PHKL_27813", "PHKL_28152", "PHKL_28202", "PHKL_29434", "PHKL_30578", "PHKL_33268", "PHKL_35828");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"OS-Core.CORE2-KRN", version:"B.11.00")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
