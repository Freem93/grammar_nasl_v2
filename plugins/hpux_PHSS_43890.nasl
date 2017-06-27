#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_43890. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(73719);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/03 14:10:43 $");

  script_cve_id("CVE-2013-2344", "CVE-2013-2345", "CVE-2013-2346", "CVE-2013-2347", "CVE-2013-2348", "CVE-2013-2349", "CVE-2013-2350", "CVE-2013-6194", "CVE-2013-6195");
  script_bugtraq_id(64647);
  script_osvdb_id(101625, 101626, 101627, 101628, 101629, 101630, 101631, 101634, 101635);
  script_xref(name:"HP", value:"emr_na-c03822422");

  script_name(english:"HP-UX PHSS_43890 : s700_800 11.X OV DP7.00 HP-UX IA/PA - Core patch");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.X OV DP7.00 HP-UX IA/PA - Core patch : 

Potential security vulnerabilities have been identified with HP Data
Protector. These vulnerabilities could be remotely exploited to allow
an increase of privilege, create a Denial of Service (DoS), or execute
arbitrary code. References: CVE-2013-2344 (ZDI-CAN-1866, SSRT101217)
CVE-2013-2345 (ZDI-CAN-1869, SSRT101218) CVE-2013-2346 (ZDI-CAN-1870,
SSRT101219) CVE-2013-2347 (ZDI-CAN-1885, SSRT101220) CVE-2013-2348
(ZDI-CAN-1892, SSRT101221) CVE-2013-2349 (ZDI-CAN-1896, SSRT101222)
CVE-2013-2350 (ZDI-CAN-1897, SSRT101223) CVE-2013-6194 (ZDI-CAN-1905,
SSRT101233) CVE-2013-6195 (ZDI-CAN-2008, SSRT101348)."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c03822422
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fe03aaf8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_43890 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'HP Data Protector Backup Client Service Directory Traversal');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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

if (!hpux_check_ctx(ctx:"11.11 11.23 11.31"))
{
  exit(0, "The host is not affected since PHSS_43890 applies to a different OS release.");
}

patches = make_list("PHSS_43890");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"DATA-PROTECTOR.OMNI-CF-P", version:"A.07.00")) flag++;
if (hpux_check_patch(app:"DATA-PROTECTOR.OMNI-CORE", version:"A.07.00")) flag++;
if (hpux_check_patch(app:"DATA-PROTECTOR.OMNI-CORE-IS", version:"A.07.00")) flag++;
if (hpux_check_patch(app:"DATA-PROTECTOR.OMNI-INTEG-P", version:"A.07.00")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
