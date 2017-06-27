#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHNE_31034. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(16971);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/04/20 00:36:49 $");

  script_cve_id("CVE-2004-1332");
  script_xref(name:"HP", value:"emr_na-c00951289");
  script_xref(name:"HP", value:"emr_na-c01035676");
  script_xref(name:"HP", value:"HPSBUX01050");
  script_xref(name:"HP", value:"HPSBUX01118");
  script_xref(name:"HP", value:"SSRT3456");
  script_xref(name:"HP", value:"SSRT4883");

  script_name(english:"HP-UX PHNE_31034 : s700_800 11.04 (VVOS) ftpd(1M) and ftp(1) patch");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.04 (VVOS) ftpd(1M) and ftp(1) patch : 

The remote HP-UX host is affected by multiple vulnerabilities :

  - A potential security vulnerability has been identified
    with HP-UX running ftpd, where a buffer overflow in ftpd
    could be remotely exploited to allow an unauthorized
    user to gain privileged access. (HPSBUX01118 SSRT4883)

  - A potential security vulnerability has been identified
    with HP-UX running ftp where the vulnerability could be
    exploited remotely to allow unauthorized access.
    (HPSBUX01050 SSRT3456)"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00951289
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?353e3f75"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01035676
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0e3b95fe"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHNE_31034 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/04/05");
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
  exit(0, "The host is not affected since PHNE_31034 applies to a different OS release.");
}

patches = make_list("PHNE_31034", "PHNE_32813", "PHNE_34077");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"InternetSrvcs.INET-ENG-A-MAN", version:"B.11.04")) flag++;
if (hpux_check_patch(app:"InternetSrvcs.INETSVCS-RUN", version:"B.11.04")) flag++;
if (hpux_check_patch(app:"VirtualVaultOS.VVOS-AUX-IA", version:"B.11.04")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
