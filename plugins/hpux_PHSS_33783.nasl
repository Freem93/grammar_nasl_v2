#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_33783. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(19825);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/04/20 00:41:03 $");

  script_xref(name:"HP", value:"emr_na-c00604164");

  script_name(english:"HP-UX PHSS_33783 : s700_800 11.X OV NNM7.50 CGI PA RISC Intermediate Patch");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.X OV NNM7.50 CGI PA RISC Intermediate Patch : 

Potential vulnerabilities have been identified with HP OpenView
Network Node Manager (OV NNM). These vulnerabilities could be
exploited remotely by an unauthorized user to gain privileged access.
References: Portcullis Security Advisory 05-014."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00604164
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5b3952af"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_33783 or subsequent."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/05");
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

if (!hpux_check_ctx(ctx:"11.00 11.11 11.23", proc:"parisc"))
{
  exit(0, "The host is not affected since PHSS_33783 applies to a different OS release / architecture.");
}

patches = make_list("PHSS_33783", "PHSS_33875", "PHSS_34098", "PHSS_34870");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"OVNNMgr.OVNNM-RUN", version:"B.07.50.00")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
