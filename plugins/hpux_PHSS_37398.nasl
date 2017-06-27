#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_37398. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(29972);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2014/03/12 16:06:50 $");

  script_cve_id("CVE-2007-3872");
  script_osvdb_id(39527);
  script_xref(name:"HP", value:"emr_na-c01110576");
  script_xref(name:"IAVT", value:"2007-T-0033");
  script_xref(name:"HP", value:"SSRT061260");

  script_name(english:"HP-UX PHSS_37398 : HP OpenView Operations (OVO) Agents Running Shared Trace Service, Remote Arbitrary Code Execution (HPSBMA02239 SSRT061260 rev.3)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.X OV OVO8.X Core Agt Solaris A.08.17.3 : 

A potential security vulnerability has been identified in HP OpenView
Operations (OVO) Agents running Shared Trace Service. The
vulnerability could be remotely exploited to execute arbitrary code."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01110576
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0a84be10"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_37398 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'HP OpenView Operations OVTrace Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/29");
  script_set_attribute(attribute:"patch_modification_date", value:"2008/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/15");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2014 Tenable Network Security, Inc.");
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
  exit(0, "The host is not affected since PHSS_37398 applies to a different OS release.");
}

patches = make_list("OASOL_00001", "PHSS_37398", "PHSS_37677", "PHSS_38511", "PHSS_39501");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"OVO-CLT-NLS.OVO-CLT-SCH", version:"A.08.10.160")) flag++;
if (hpux_check_patch(app:"OVO-CLT.OVO-SOL-CLT", version:"A.08.10.160")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:hpux_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
