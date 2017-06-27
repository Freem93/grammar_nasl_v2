#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_36123. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(26150);
  script_version("$Revision: 1.25 $");
  script_cvs_date("$Date: 2015/03/19 14:42:13 $");

  script_cve_id("CVE-2006-6101", "CVE-2006-6102", "CVE-2006-6103");
  script_bugtraq_id(21968);
  script_osvdb_id(32084, 32085, 32086);
  script_xref(name:"HP", value:"emr_na-c01075678");
  script_xref(name:"HP", value:"HPSBUX02225");
  script_xref(name:"HP", value:"SSRT071295");

  script_name(english:"HP-UX PHSS_36123 : HP-UX Running Xserver, Local Denial of Service (DoS) (HPSBUX02225 SSRT071295 rev.1)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.31 Xserver cumulative patch : 

Potential security vulnerabilities have been identified with HP-UX
running Xserver. These vulnerabilities could be exploited by a local
user to create a Denial of Service (DoS)."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01075678
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?31324b64"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_36123 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/25");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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
  exit(0, "The host is not affected since PHSS_36123 applies to a different OS release.");
}

patches = make_list("PHSS_36123", "PHSS_37621", "PHSS_37973", "PHSS_38840", "PHSS_39258", "PHSS_39706", "PHSS_39876", "PHSS_40217", "PHSS_40809", "PHSS_41106", "PHSS_41259", "PHSS_42881");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"Xserver.AGRM", version:"B.11.31")) flag++;
if (hpux_check_patch(app:"Xserver.DDX-ADVANCED", version:"B.11.31")) flag++;
if (hpux_check_patch(app:"Xserver.DDX-LOAD", version:"B.11.31")) flag++;
if (hpux_check_patch(app:"Xserver.DDX-SAM", version:"B.11.31")) flag++;
if (hpux_check_patch(app:"Xserver.DDX-SLS", version:"B.11.31")) flag++;
if (hpux_check_patch(app:"Xserver.DDX-UTILS", version:"B.11.31")) flag++;
if (hpux_check_patch(app:"Xserver.OEM-SERVER", version:"B.11.31")) flag++;
if (hpux_check_patch(app:"Xserver.OEM-SERVER-PA", version:"B.11.31")) flag++;
if (hpux_check_patch(app:"Xserver.X11-SERV", version:"B.11.31")) flag++;
if (hpux_check_patch(app:"Xserver.X11-SERV-MAN", version:"B.11.31")) flag++;
if (hpux_check_patch(app:"Xserver.XEXT-DBE", version:"B.11.31")) flag++;
if (hpux_check_patch(app:"Xserver.XEXT-DPMS", version:"B.11.31")) flag++;
if (hpux_check_patch(app:"Xserver.XEXT-HPCR", version:"B.11.31")) flag++;
if (hpux_check_patch(app:"Xserver.XEXT-MBX", version:"B.11.31")) flag++;
if (hpux_check_patch(app:"Xserver.XEXT-RECORD", version:"B.11.31")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
