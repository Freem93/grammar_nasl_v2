#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHNE_34672. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(22432);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2014/03/12 15:37:24 $");

  script_cve_id("CVE-2006-4795");
  script_osvdb_id(28784);
  script_xref(name:"HP", value:"emr_na-c00768665");
  script_xref(name:"HP", value:"HPSBUX02151");
  script_xref(name:"HP", value:"SSRT051021");

  script_name(english:"HP-UX PHNE_34672 : HP-UX Running ARPA Transport Software, Local Denial of Service (DoS) (HPSBUX02151 SSRT051021 rev.1)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.11 cumulative ARPA Transport patch : 

A potential security vulnerability has been identified with HP-UX
running ARPA transport software. The vulnerability could be exploited
by a local, authenticated user to create a Denial of Service (DoS)."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00768665
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5fb43013"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHNE_34672 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/09/22");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");
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
  exit(0, "The host is not affected since PHNE_34672 applies to a different OS release.");
}

patches = make_list("PHNE_34672", "PHNE_35183", "PHNE_35351", "PHNE_36125", "PHNE_37671", "PHNE_37898", "PHNE_38678", "PHNE_39386", "PHNE_42029");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"Networking.NET-KRN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"Networking.NET-PRG", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"Networking.NET-RUN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"Networking.NET-RUN-64", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"Networking.NET2-KRN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"Networking.NMS2-KRN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"Networking.NW-ENG-A-MAN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"OS-Core.CORE-KRN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"OS-Core.CORE2-KRN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"OS-Core.SYS-ADMIN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"ProgSupport.C-INC", version:"B.11.11")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:hpux_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
