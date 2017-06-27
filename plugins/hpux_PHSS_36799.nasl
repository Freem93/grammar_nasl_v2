#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_36799. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(43138);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/11/18 20:51:41 $");

  script_cve_id("CVE-2007-2280", "CVE-2007-2281", "CVE-2009-3844");
  script_osvdb_id(60852, 61205, 61206);
  script_xref(name:"TRA", value:"TRA-2009-04");
  script_xref(name:"HP", value:"emr_na-c01124817");
  script_xref(name:"HP", value:"emr_na-c01943909");
  script_xref(name:"HP", value:"SSRT061258");
  script_xref(name:"HP", value:"SSRT061259");
  script_xref(name:"HP", value:"SSRT090113");

  script_name(english:"HP-UX PHSS_36799 : s700_800 11.X OV DP5.50 PA RISC patch - CS packet");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.X OV DP5.50 PA RISC patch - CS packet : 

The remote HP-UX host is affected by multiple vulnerabilities :

  - Potential security vulnerabilities have been identified
    with HP OpenView Storage Data Protector running on
    HP-UX, Windows, Linux and Solaris. These vulnerabilities
    could be exploited remotely to execute arbitrary code.
    (HPSBMA02252 SSRT061258, SSRT061259)

  - A potential security vulnerability has been identified
    with OpenView Data Protector Application Recovery
    Manager version 5.5 and 6.0. The vulnerability could be
    exploited remotely to create a denial of service (DoS).
    (HPSBMA02481 SSRT090113)"
  );
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2009-04");
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01124817
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5bd45cd2"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01943909
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0a593fc9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_36799 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'HP OmniInet.exe MSG_PROTOCOL Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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

if (!hpux_check_ctx(ctx:"11.00 11.11 11.23", proc:"parisc"))
{
  exit(0, "The host is not affected since PHSS_36799 applies to a different OS release / architecture.");
}

patches = make_list("PHSS_36799", "PHSS_37827", "PHSS_38726");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"DATA-PROTECTOR.OMNI-CS", version:"A.05.50")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
