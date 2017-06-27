#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_37702. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(32156);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/20 14:03:00 $");

  script_cve_id("CVE-2007-5360", "CVE-2008-0003");
  script_bugtraq_id(27172);
  script_xref(name:"HP", value:"emr_na-c01438409");
  script_xref(name:"HP", value:"SSRT080000");

  script_name(english:"HP-UX PHSS_37702 : HP-UX running WBEM Services, Remote Execution of Arbitrary Code, Gain Extended Privileges (HPSBMA02331 SSRT080000 rev.3)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.11 HP WBEM Services A.02.05.08 : 

Potential security vulnerabilities have been identified with HP-UX
running WBEM Services. These vulnerabilities could be exploited
remotely to execute arbitrary code or to gain extended privileges."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01438409
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9d738e39"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_37702 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/28");
  script_set_attribute(attribute:"patch_modification_date", value:"2009/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
  exit(0, "The host is not affected since PHSS_37702 applies to a different OS release.");
}

patches = make_list("PHSS_37702");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"WBEMServices.WBEM-CORE", version:"A.02.05.08")) flag++;
if (hpux_check_patch(app:"WBEMServices.WBEM-CORE-COM", version:"A.02.05.08")) flag++;
if (hpux_check_patch(app:"WBEMServices.WBEM-MAN", version:"A.02.05.08")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
