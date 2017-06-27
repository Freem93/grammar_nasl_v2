#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHNE_33790. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(20201);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2014/03/12 15:37:24 $");

  script_cve_id("CVE-2005-3565", "CVE-2006-4188");
  script_osvdb_id(20679, 27959);
  script_xref(name:"HP", value:"emr_na-c00543854");
  script_xref(name:"HP", value:"emr_na-c00746980");
  script_xref(name:"HP", value:"HPSBUX02072");
  script_xref(name:"HP", value:"HPSBUX02139");
  script_xref(name:"HP", value:"SSRT051014");
  script_xref(name:"HP", value:"SSRT5981");

  script_name(english:"HP-UX PHNE_33790 : s700_800 11.00 r-commands cumulative mega-patch");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.00 r-commands cumulative mega-patch : 

The remote HP-UX host is affected by multiple vulnerabilities :

  - A potential vulnerability hs been identified with HP-UX
    systems running in Trusted Mode. The vulnerability could
    be exploited remotely to gain unauthorized access.
    (HPSBUX02072 SSRT051014)

  - A potential security vulnerability has been identified
    with HP-UX running the LP subsystem. The vulnerability
    could be exploited by a remote user to create a Denial
    of Service (DoS). (HPSBUX02139 SSRT5981)"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00543854
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?06b15d64"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00746980
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?767d3fa2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHNE_33790 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/11/15");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/11/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
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

if (!hpux_check_ctx(ctx:"11.00"))
{
  exit(0, "The host is not affected since PHNE_33790 applies to a different OS release.");
}

patches = make_list("PHNE_33790");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"InternetSrvcs.INET-ENG-A-MAN", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"InternetSrvcs.INETSVCS-RUN", version:"B.11.00")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
