#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_32196. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(26746);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2013/04/20 00:41:03 $");

  script_cve_id("CVE-2004-0965");
  script_xref(name:"HP", value:"emr_na-c00901390");
  script_xref(name:"HP", value:"HPSBUX01088");
  script_xref(name:"HP", value:"SSRT4807");

  script_name(english:"HP-UX PHSS_32196 : HP-UX stmkfont Local Unauthorized Privileged Access (HPSBUX01088 SSRT4807 rev.2)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.04 (VVOS) X Font Server Patch : 

A potential security vulnerability has been reported with the HP-UX
stmkfont program. This vulnerability can be exploited to allow local
unauthorized access to resources owned by group 'bin.'."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00901390
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?71ae34fe"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_32196 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/03");
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

if (!hpux_check_ctx(ctx:"11.04"))
{
  exit(0, "The host is not affected since PHSS_32196 applies to a different OS release.");
}

patches = make_list("PHSS_32196");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"X11.X11-FONTSRV", version:"B.11.04")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
