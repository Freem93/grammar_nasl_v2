#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2016/11/10. Deprecated by aix_powerha_advisory.nasl.
#

include("compat.inc");

if (description)
{
  script_id(85943);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/11/10 18:24:50 $");

  script_cve_id("CVE-2015-5005");

  script_name(english:"AIX 6.1 TL 0 : powerha (IV76943) (deprecated)");
  script_summary(english:"Check for APAR IV76943");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"IBM PowerHA SystemMirror has a systems management feature (CSPOC)
which includes an option to allow users to change their password
cluster-wide. Once added to this list, a non-root user may be able to
exploit a vulnerability in one of the scripts shipped with the product
to switch user (su) to the root user.

This plugin has been deprecated and replaced with
aix_powerha_advisory.nasl (plugin ID 94674) to more accurately check
for multiple potential fixes.");
  script_set_attribute(attribute:"see_also", value:"http://aix.software.ibm.com/aix/efixes/security/powerha_advisory.asc");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");


  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:6.1");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"AIX Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version");

  exit(0);
}

exit(0, "This plugin has been deprecated. Use aix_powerha_advisory.nasl (plugin ID 94674) instead.");

include("audit.inc");
include("global_settings.inc");
include("aix.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if ( ! get_kb_item("Host/AIX/version") ) audit(AUDIT_OS_NOT, "AIX");
if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

if ( get_kb_item("Host/AIX/emgr_failure" ) ) exit(0, "This iFix check is disabled because : "+get_kb_item("Host/AIX/emgr_failure") );

flag = 0;

if (aix_check_ifix(release:"6.1", ml:"00", patch:"IV76943_61", package:"cluster.es.client.rte", minfilesetver:"6.1.0.0", maxfilesetver:"6.1.0.11") < 0) flag++;
if (aix_check_ifix(release:"6.1", ml:"00", patch:"IV76943_61", package:"cluster.es.cspoc.cmds", minfilesetver:"6.1.0.0", maxfilesetver:"6.1.0.15") < 0) flag++;
if (aix_check_ifix(release:"6.1", ml:"00", patch:"IV76943_61", package:"cluster.es.cspoc.rte", minfilesetver:"6.1.0.0", maxfilesetver:"6.1.0.14") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"02", patch:"IV76943", package:"cluster.es.client.rte", minfilesetver:"7.1.2.0", maxfilesetver:"7.1.2.3") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"02", patch:"IV76943", package:"cluster.es.cspoc.cmds", minfilesetver:"7.1.2.0", maxfilesetver:"7.1.2.6") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"02", patch:"IV76943", package:"cluster.es.cspoc.rte", minfilesetver:"7.1.2.0", maxfilesetver:"7.1.2.6") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"03", patch:"IV76943", package:"cluster.es.client.rte", minfilesetver:"7.1.3.0", maxfilesetver:"7.1.3.2") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"03", patch:"IV76943", package:"cluster.es.cspoc.cmds", minfilesetver:"7.1.3.0", maxfilesetver:"7.1.3.3") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"03", patch:"IV76943", package:"cluster.es.cspoc.rte", minfilesetver:"7.1.3.0", maxfilesetver:"7.1.3.3") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:aix_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
