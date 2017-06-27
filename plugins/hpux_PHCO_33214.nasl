#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHCO_33214. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(21547);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2014/03/12 15:37:23 $");

  script_cve_id("CVE-2006-1509");
  script_osvdb_id(24326);
  script_xref(name:"HP", value:"emr_na-c00619550");
  script_xref(name:"HP", value:"HPSBUX02103");
  script_xref(name:"HP", value:"SSRT5953");

  script_name(english:"HP-UX PHCO_33214 : HP-UX passwd(1) Local Denial of Service (DoS) (HPSBUX02103 SSRT5953 rev.3)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.11 passwd(1) cumulative patch : 

A potential security vulnerability has been identified with HP-UX
running /sbin/passwd which could be locally exploited to create a
Denial of Service (DoS)."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00619550
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?583442b8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHCO_33214 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/05/17");
  script_set_attribute(attribute:"patch_modification_date", value:"2006/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/05/13");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/03/26");
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
  exit(0, "The host is not affected since PHCO_33214 applies to a different OS release.");
}

patches = make_list("PHCO_33214", "PHCO_36465", "PHCO_39767");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"OS-Core.UX-CORE", version:"B.11.11")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:hpux_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
