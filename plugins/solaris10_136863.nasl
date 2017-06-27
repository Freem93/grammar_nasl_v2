#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#

include("compat.inc");

if (description)
{
  script_id(37316);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2014/12/03 05:40:37 $");

  script_cve_id("CVE-2009-0651");
  script_xref(name:"IAVT", value:"2009-T-0014");

  script_name(english:"Solaris 10 (sparc) : 136863-01");
  script_summary(english:"Check for patch 136863-01");

  script_set_attribute(attribute:"synopsis", value:"The remote host is missing Sun Security Patch number 136863-01");
  script_set_attribute(attribute:"description", value:
"VERITAS NetBackup 6.5 Product Release Hotf. Date this patch was last
updated by Sun : Feb/24/09");
  script_set_attribute(attribute:"see_also", value:"https://support.oracle.com/epmos/faces/DocContentDisplay?id=1682359.1");
  script_set_attribute(attribute:"see_also", value:"http://www.symantec.com/business/theme.jsp?themeid=sun-support");
  script_set_attribute(attribute:"solution", value:"You should install this patch for your system to be up-to-date.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");

  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

vendornote = '\nThis patch is no longer available from Oracle, as the Symantec Veritas\n' +
'NetBackup support contract with Oracle has ended. The patch has been\n' +
'removed from Oracle repositories.\n\n' +
'Please contact the vendor for product support :\n' +
'http://www.symantec.com/theme.jsp?themeid=sun-support';

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"136863-01", obsoleted_by:"127655-04 ", package:"SYMCnetbp", version:"6.5,REV=2007.07.24.02.54") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report() + vendornote);
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
