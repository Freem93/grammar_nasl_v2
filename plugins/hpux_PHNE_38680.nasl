#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHNE_38680. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(39001);
  script_version("$Revision: 1.32 $");
  script_cvs_date("$Date: 2016/12/01 15:13:43 $");

  script_cve_id("CVE-2008-2476", "CVE-2008-4404", "CVE-2009-0418");
  script_bugtraq_id(31529);
  script_xref(name:"HP", value:"emr_na-c01662367");
  script_xref(name:"IAVB", value:"2008-B-0070");
  script_xref(name:"HP", value:"HPSBUX02407");
  script_xref(name:"HP", value:"SSRT080107");

  script_name(english:"HP-UX PHNE_38680 : HP-UX Running IPv6, Remote Denial of Service (DoS) and Unauthorized Access (HPSBUX02407 SSRT080107 rev.1)");
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
running IPv6. This vulnerability could be exploited remotely resulting
in a Denial of Service (DoS) and unauthorized access."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01662367
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2e35c679"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHNE_38680 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/12");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
  exit(0, "The host is not affected since PHNE_38680 applies to a different OS release.");
}

patches = make_list("PHNE_38680", "PHNE_39203", "PHNE_39709", "PHNE_40900", "PHNE_41004", "PHNE_41617", "PHNE_41714", "PHNE_42017", "PHNE_42470", "PHNE_43412", "PHNE_43814", "PHNE_44266", "PHNE_44547");
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
if (hpux_check_patch(app:"Networking.NET-RUN-64", version:"B.11.31")) flag++;
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
