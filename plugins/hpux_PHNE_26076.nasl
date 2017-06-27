#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHNE_26076. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(18398);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/11/23 14:38:50 $");

  script_cve_id("CVE-2004-0790", "CVE-2004-0791", "CVE-2004-1060");
  script_bugtraq_id(13124);
  script_osvdb_id(15457, 15618);
  script_xref(name:"CERT", value:"532967");
  script_xref(name:"HP", value:"emr_na-c00576017");
  script_xref(name:"HP", value:"HPSBUX01164");
  script_xref(name:"HP", value:"SSRT4884");

  script_name(english:"HP-UX PHNE_26076 : HP-UX TCP/IP Remote Denial of Service (DoS) (HPSBUX01164 SSRT4884 rev.9)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.04 (VVOS) ndd(1M) cumulative patch : 

A potential security vulnerability has been identified with HP-UX
running TCP/IP. This vulnerability could be remotely exploited by an
unauthorized user to cause a Denial of Service(DoS). References: NISCC
VU#532967, CAN-2004-0790, CAN-2004-0791, CAN-2004-1060."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00576017
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3a3e8ad7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHNE_26076 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/03/21");
  script_set_attribute(attribute:"patch_modification_date", value:"2006/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/05/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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
  exit(0, "The host is not affected since PHNE_26076 applies to a different OS release.");
}

patches = make_list("PHNE_26076", "PHNE_33789");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"Networking.NET-RUN", version:"B.11.04")) flag++;
if (hpux_check_patch(app:"Networking.NW-ENG-A-MAN", version:"B.11.04")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:hpux_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
