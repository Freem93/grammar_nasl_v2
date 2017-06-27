#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHKL_32669. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(19540);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2015/04/24 14:14:49 $");

  script_osvdb_id(19041);
  script_xref(name:"HP", value:"emr_na-c00897380");
  script_xref(name:"HP", value:"HPSBUX01218");
  script_xref(name:"HP", value:"SSRT4702");

  script_name(english:"HP-UX PHKL_32669 : HPSBUX01218 SSRT4702 rev 2. - HP-UX Running Veritas VxFS 3.3/3.5, Local Unauthorized Access");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.11 VxFS cumulative patch : 

A potential vulnerability has been identified in HP-UX running the
Veritas File System (VxFS) that may allow a local authorized user
access to unauthorized data."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00897380
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d460b32c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHKL_32669 or subsequent."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/08/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
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

if (!hpux_check_ctx(ctx:"11.11"))
{
  exit(0, "The host is not affected since PHKL_32669 applies to a different OS release.");
}

patches = make_list("PHKL_32669", "PHKL_33258", "PHKL_33484", "PHKL_34039", "PHKL_34665", "PHKL_34805", "PHKL_41409", "PHKL_41587", "PHKL_41709", "PHKL_42503", "PHKL_44220");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"JFS.VXFS-BASE-KRN", version:"B.11.11")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
