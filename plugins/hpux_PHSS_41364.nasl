#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_41364. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(56842);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/01/15 16:37:16 $");

  script_cve_id("CVE-2011-0273", "CVE-2011-1864");
  script_bugtraq_id(45929, 48178);
  script_osvdb_id(70621, 72864);
  script_xref(name:"HP", value:"emr_na-c02688353");
  script_xref(name:"HP", value:"emr_na-c02712867");
  script_xref(name:"HP", value:"SSRT100138");
  script_xref(name:"HP", value:"SSRT100324");

  script_name(english:"HP-UX PHSS_41364 : s700_800 11.X OV DP6.11 HP-UX IA64 - Core patch");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.X OV DP6.11 HP-UX IA64 - Core patch : 

The remote HP-UX host is affected by multiple vulnerabilities :

  - A potential security vulnerability has been identified
    with HP OpenView Storage Data Protector. The
    vulnerability could be remotely exploited to execute
    arbitrary code. (HPSBMA02631 SSRT100324)

  - A potential security vulnerability has been identified
    with HP OpenView Storage Data Protector. The
    vulnerability could be remotely exploited to execute
    arbitrary code. (HPSBMA02625 SSRT100138)"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02688353
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1bea18ae"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02712867
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a7685e40"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_41364 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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

if (!hpux_check_ctx(ctx:"11.23 11.31", proc:"ia64"))
{
  exit(0, "The host is not affected since PHSS_41364 applies to a different OS release / architecture.");
}

patches = make_list("PHSS_41364", "PHSS_41803", "PHSS_41955", "PHSS_42169", "PHSS_42699");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"DATA-PROTECTOR.OMNI-CORE", version:"A.06.11")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
