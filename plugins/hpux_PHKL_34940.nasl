#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHKL_34940. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(22057);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2014/03/12 15:37:24 $");

  script_cve_id("CVE-2006-2551");
  script_osvdb_id(25896);
  script_xref(name:"HP", value:"emr_na-c00676467");
  script_xref(name:"HP", value:"HPSBUX02120");
  script_xref(name:"HP", value:"SSRT051057");

  script_name(english:"HP-UX PHKL_34940 : HP-UX Local Denial of Service (DoS) (HPSBUX02120 SSRT051057 rev.2)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.04 (VVOS) Timers disabling, early SIGXCPU : 

A potential security vulnerability has been identified in the HP-UX
kernel. The potential vulnerability could be exploited by a local
authorized user to create a Denial of Service (DoS)."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00676467
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9a1eb382"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHKL_34940 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/05");
  script_set_attribute(attribute:"patch_modification_date", value:"2006/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/18");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/23");
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

if (!hpux_check_ctx(ctx:"11.04"))
{
  exit(0, "The host is not affected since PHKL_34940 applies to a different OS release.");
}

patches = make_list("PHKL_34940");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"OS-Core.CORE2-KRN", version:"B.11.04")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:hpux_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
