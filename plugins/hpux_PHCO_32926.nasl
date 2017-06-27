#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHCO_32926. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(18395);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2014/03/12 15:37:23 $");

  script_cve_id("CVE-2005-1771", "CVE-2006-1509");
  script_osvdb_id(16869, 24326);
  script_xref(name:"HP", value:"emr_na-c00619550");
  script_xref(name:"HP", value:"emr_na-c00892559");
  script_xref(name:"HP", value:"HPSBUX01165");
  script_xref(name:"HP", value:"HPSBUX02103");
  script_xref(name:"HP", value:"SSRT5899");
  script_xref(name:"HP", value:"SSRT5953");

  script_name(english:"HP-UX PHCO_32926 : s700_800 11.23 libpam_unix cumulative patch");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.23 libpam_unix cumulative patch : 

The remote HP-UX host is affected by multiple vulnerabilities :

  - A potential security vulnerability has been identified
    with HP-UX trusted systems where the vulnerability may
    be exploited to allow remote unauthorized access.
    (HPSBUX01165 SSRT5899)

  - A potential security vulnerability has been identified
    with HP-UX running /sbin/passwd which could be locally
    exploited to create a Denial of Service (DoS).
    (HPSBUX02103 SSRT5953)"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00892559
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?987adafe"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00619550
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?583442b8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHCO_32926 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/05/23");
  script_set_attribute(attribute:"patch_modification_date", value:"2006/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/05/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/26");
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

if (!hpux_check_ctx(ctx:"11.23"))
{
  exit(0, "The host is not affected since PHCO_32926 applies to a different OS release.");
}

patches = make_list("PHCO_32926", "PHCO_33488", "PHCO_34215", "PHCO_35251", "PHCO_35850", "PHCO_36759", "PHCO_37070", "PHCO_37076", "PHCO_39230", "PHCO_39711", "PHCO_40360", "PHCO_40836");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"OS-Core.CORE-ENG-A-MAN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"OS-Core.CORE2-64SLIB", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"OS-Core.CORE2-SHLIBS", version:"B.11.23")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
