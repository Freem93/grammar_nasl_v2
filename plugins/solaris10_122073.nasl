#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#

include("compat.inc");

if (description)
{
  script_id(26983);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2014/12/02 18:35:52 $");

  script_cve_id("CVE-2008-4339");

  script_name(english:"Solaris 10 (sparc) : 122073-04");
  script_summary(english:"Check for patch 122073-04");

  script_set_attribute(attribute:"synopsis", value:"The remote host is missing Sun Security Patch number 122073-04");
  script_set_attribute(attribute:"description", value:
"VERITAS NetBackup 6.0 Product Jumbo Patch MP7 for MP4 CD VERSION=6.
Date this patch was last updated by Sun : Sep/29/08");
  script_set_attribute(attribute:"see_also", value:"https://support.oracle.com/epmos/faces/DocContentDisplay?id=1682359.1");
  script_set_attribute(attribute:"see_also", value:"http://www.symantec.com/business/theme.jsp?themeid=sun-support");
  script_set_attribute(attribute:"solution", value:"You should install this patch for your system to be up-to-date.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/12");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
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

if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"122073-04", obsoleted_by:"", package:"VRTSnetbp", version:"6.0,REV=2006.11.09.18.12") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report() + vendornote);
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
