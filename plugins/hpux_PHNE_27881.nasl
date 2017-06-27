#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHNE_27881. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(16963);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2013/04/20 00:36:48 $");

  script_xref(name:"HP", value:"emr_na-c00957990");
  script_xref(name:"HP", value:"HPSBUX00209");
  script_xref(name:"HP", value:"SSRT2316");

  script_name(english:"HP-UX PHNE_27881 : HP-UX DNS and Resolver Libraries, Remote Execution of Arbitrary Code, Denial of Service (DoS) (HPSBUX00209 SSRT2316 rev.17)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.04 (VVOS) libnss_dns DNS backend patch : 

Potential buffer overflows in DNS resolver libraries."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00957990
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?821eb02f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHNE_27881 or subsequent."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/06/10");
  script_set_attribute(attribute:"patch_modification_date", value:"2007/04/13");
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

if (!hpux_check_ctx(ctx:"11.04"))
{
  exit(0, "The host is not affected since PHNE_27881 applies to a different OS release.");
}

patches = make_list("PHNE_27881", "PHNE_30007");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"NFS.NFS-64SLIB", version:"B.11.04")) flag++;
if (hpux_check_patch(app:"NFS.NFS-SHLIBS", version:"B.11.04")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
