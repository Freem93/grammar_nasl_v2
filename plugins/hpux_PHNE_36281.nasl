#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHNE_36281. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(31615);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2016/11/30 14:40:21 $");

  script_cve_id("CVE-2007-6425");
  script_osvdb_id(40489);
  script_xref(name:"HP", value:"emr_na-c01328657");
  script_xref(name:"HP", value:"HPSBUX02306");
  script_xref(name:"HP", value:"SSRT071463");

  script_name(english:"HP-UX PHNE_36281 : HP-UX Running ARPA Transport, Remote Denial of Service (DoS) (HPSBUX02306 SSRT071463 rev.2)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.31 cumulative ARPA Transport patch : 

A potential security vulnerability has been identified with HP-UX
running ARPA Transport. The vulnerability could be exploited remotely
to create a Denial of Service (DoS)."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01328657
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9477c88d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHNE_36281 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/25");
  script_set_attribute(attribute:"patch_modification_date", value:"2008/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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

if (!hpux_check_ctx(ctx:"11.31"))
{
  exit(0, "The host is not affected since PHNE_36281 applies to a different OS release.");
}

patches = make_list("PHNE_36281", "PHNE_37899", "PHNE_38680", "PHNE_39203", "PHNE_39709", "PHNE_40900", "PHNE_41004", "PHNE_41617", "PHNE_41714", "PHNE_42017", "PHNE_42470", "PHNE_43412", "PHNE_43814", "PHNE_44266", "PHNE_44547");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"Networking.NET-PRG", version:"B.11.31")) flag++;
if (hpux_check_patch(app:"Networking.NET-RUN", version:"B.11.31")) flag++;
if (hpux_check_patch(app:"Networking.NET2-KRN", version:"B.11.31")) flag++;
if (hpux_check_patch(app:"Networking.NET2-RUN", version:"B.11.31")) flag++;
if (hpux_check_patch(app:"Networking.NMS2-KRN", version:"B.11.31")) flag++;
if (hpux_check_patch(app:"Networking.NW-ENG-A-MAN", version:"B.11.31")) flag++;
if (hpux_check_patch(app:"OS-Core.CORE2-KRN", version:"B.11.31")) flag++;
if (hpux_check_patch(app:"OS-Core.KERN-ENG-A-MAN", version:"B.11.31")) flag++;
if (hpux_check_patch(app:"OS-Core.SYS2-ADMIN", version:"B.11.31")) flag++;
if (hpux_check_patch(app:"ProgSupport.C-INC", version:"B.11.31")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
