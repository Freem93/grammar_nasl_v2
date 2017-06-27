#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHNE_33508. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(22866);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2014/03/12 15:37:24 $");

  script_cve_id("CVE-2005-0769");
  script_osvdb_id(14766);
  script_xref(name:"HP", value:"emr_na-c00717872");
  script_xref(name:"HP", value:"HPSBUX02129");
  script_xref(name:"HP", value:"SSRT061149");

  script_name(english:"HP-UX PHNE_33508 : HP-UX running SLP, Remote Unauthorized Access (HPSBUX02129 SSRT061149 rev.2)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.23 slpd(1M) patch : 

A potential security vulnerability has been identified in HP-UX when
running Service Locator Protocol (SLP).The vulnerability could be
exploited by a remote user of Service Locator Protocol (SLP) for
unauthorized access. References: SUSE-SA:2005:015."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00717872
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f8510e21"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHNE_33508 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/06/30");
  script_set_attribute(attribute:"patch_modification_date", value:"2007/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/15");
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

if (!hpux_check_ctx(ctx:"11.23"))
{
  exit(0, "The host is not affected since PHNE_33508 applies to a different OS release.");
}

patches = make_list("PHNE_33508");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"InternetSrvcs.INETSVCS2-RUN", version:"B.11.23")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
