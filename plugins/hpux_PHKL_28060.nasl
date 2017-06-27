#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHKL_28060. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(26127);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/04/16 13:48:28 $");

  script_cve_id("CVE-2007-1993");
  script_bugtraq_id(23401);
  script_osvdb_id(34897);
  script_xref(name:"HP", value:"emr_na-c00913684");
  script_xref(name:"HP", value:"HPSBUX02203");
  script_xref(name:"HP", value:"SSRT071339");

  script_name(english:"HP-UX PHKL_28060 : HP-UX Running Portable File System (PFS), Remote Increase in Privilege (HPSBUX02203 SSRT071339 rev.1)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.00 Y2k; Rock Ridge extension for ISO-9660 : 

A potential security vulnerability has been identified in HP-UX with
the Portable File System (PFS). The vulnerability could be exploited
remotely to gain an increase in privilege."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00913684
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b9f3a7ae"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHKL_28060 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/25");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/03/30");
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

if (!hpux_check_ctx(ctx:"11.00"))
{
  exit(0, "The host is not affected since PHKL_28060 applies to a different OS release.");
}

patches = make_list("PHKL_28060");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"OS-Core.CORE-KRN", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"OS-Core.CORE2-KRN", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"ProgSupport.C-INC", version:"B.11.00")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
