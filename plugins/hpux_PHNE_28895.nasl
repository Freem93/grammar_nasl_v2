#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHNE_28895. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(16569);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2013/04/20 00:36:48 $");

  script_cve_id("CVE-2003-1087");
  script_xref(name:"HP", value:"emr_na-c00905565");
  script_xref(name:"HP", value:"HPSBUX00264");
  script_xref(name:"HP", value:"SSRT3460");

  script_name(english:"HP-UX PHNE_28895 : HP-UX Running on HP9000 Series 700/800, Denial of Service (DoS) (HPSBUX00264 SSRT3460 rev.5)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.11 cumulative ARPA Transport patch : 

Certain network traffic can cause programs to fail."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00905565
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6f66782d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHNE_28895 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/06/02");
  script_set_attribute(attribute:"patch_modification_date", value:"2007/03/22");
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

if (!hpux_check_ctx(ctx:"11.11"))
{
  exit(0, "The host is not affected since PHNE_28895 applies to a different OS release.");
}

patches = make_list("PHNE_28895", "PHNE_29887", "PHNE_31247", "PHNE_33159", "PHNE_33628", "PHNE_34135", "PHNE_34672", "PHNE_35183", "PHNE_35351", "PHNE_36125", "PHNE_37671", "PHNE_37898", "PHNE_38678", "PHNE_39386", "PHNE_42029");
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
