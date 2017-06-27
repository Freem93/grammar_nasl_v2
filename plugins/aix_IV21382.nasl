# @DEPRECATED@
#
# This script has been deprecated as the associated patch has
# been replaced.
#
# Disabled on 2014/06/02.
#

#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory libodm_advisory.asc.
#

include("compat.inc");

if (description)
{
  script_id(64307);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/06/02 11:02:14 $");

  script_cve_id("CVE-2012-2179");

  script_name(english:"AIX 7.1 TL 0 : libodm (IV21382)");
  script_summary(english:"Check for APAR IV21382");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote AIX host is missing a security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"AIX could allow a arbitrary file overwrite symlink vulnerability due
to libodm.a bug."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aix.software.ibm.com/aix/efixes/security/libodm_advisory.asc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the appropriate interim fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:7.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
  script_family(english:"AIX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version");

  exit(0);
}

# Deprecated.
exit(0, "The associated patch has been replaced.");




include("audit.inc");
include("global_settings.inc");
include("aix.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if ( ! get_kb_item("Host/AIX/version") ) audit(AUDIT_OS_NOT, "AIX");
if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

if ( get_kb_item("Host/AIX/emgr_failure" ) ) exit(0, "This iFix check is disabled because : "+get_kb_item("Host/AIX/emgr_failure") );

flag = 0;

if (aix_check_ifix(release:"7.1", ml:"00", sp:"05", patch:"IV21382", package:"bos.rte.odm", minfilesetver:"7.1.0.0", maxfilesetver:"7.1.0.15") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"00", sp:"06", patch:"IV21382.71", package:"bos.rte.odm", minfilesetver:"7.1.0.0", maxfilesetver:"7.1.0.15") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:aix_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
