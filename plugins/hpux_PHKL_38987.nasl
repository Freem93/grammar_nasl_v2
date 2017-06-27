#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHKL_38987. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(35066);
  script_version("$Revision: 1.40 $");
  script_cvs_date("$Date: 2016/11/23 14:38:50 $");

  script_cve_id("CVE-2008-4416");
  script_osvdb_id(50409);
  script_xref(name:"HP", value:"emr_na-c01615952");
  script_xref(name:"HP", value:"HPSBUX02389");
  script_xref(name:"HP", value:"SSRT080141");

  script_name(english:"HP-UX PHKL_38987 : HP-UX, Local Denial of Service (DoS) (HPSBUX02389 SSRT080141 rev.1)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.31 vm cumulative patch : 

A potential security vulnerability has been identified in HP-UX. The
vulnerability could be exploited locally to create a denial of service
(DoS)."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01615952
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?24c4333a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHKL_38987 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/09");
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

if (!hpux_check_ctx(ctx:"11.31"))
{
  exit(0, "The host is not affected since PHKL_38987 applies to a different OS release.");
}

patches = make_list("PHKL_38651", "PHKL_38949", "PHKL_38987", "PHKL_39401", "PHKL_39747", "PHKL_40130", "PHKL_40240", "PHKL_40441", "PHKL_40942", "PHKL_41005", "PHKL_41355", "PHKL_41362", "PHKL_41588", "PHKL_41969", "PHKL_41972", "PHKL_42444", "PHKL_42850", "PHKL_43213", "PHKL_43513", "PHKL_43544", "PHKL_43775", "PHKL_43897", "PHKL_44170", "PHKL_44230", "PHKL_44270", "PHKL_44278", "PHKL_44298", "PHKL_44417", "PHKL_44461", "PHKL_44500", "PHKL_44510", "PHKL_44565");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"OS-Core.CORE-ENG-A-MAN", version:"B.11.31")) flag++;
if (hpux_check_patch(app:"OS-Core.CORE2-KRN", version:"B.11.31")) flag++;
if (hpux_check_patch(app:"OS-Core.KERN-ENG-A-MAN", version:"B.11.31")) flag++;
if (hpux_check_patch(app:"ProgSupport.C-INC", version:"B.11.31")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:hpux_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
