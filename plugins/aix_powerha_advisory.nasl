#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory powerha_advisory.asc.
#

include("compat.inc");

if (description)
{
  script_id(94674);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/11/11 19:58:28 $");

  script_cve_id("CVE-2015-5005");
  script_bugtraq_id(76948);
  script_osvdb_id(127435);

  script_name(english:"AIX 6.1 / 7.1.2 / 7.1.3 : IBM PowerHA SystemMirror CSPOC Privilege Escalation");
  script_summary(english:"Checks the version of the PowerHA packages and iFixes.");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host is missing a security patch.");
  script_set_attribute(attribute:"description", value:
"The remote AIX host is running a version of IBM PowerHA SystemMirror
that is missing a security patch. It is, therefore, affected by a
privilege escalation vulnerability in the Cluster Single Point of
Control (CSPOC) feature that occurs when adding an authenticated,
remote user to the list that allows cluster-wide changing of the
password. An authenticated, remote attacker who has been added to this
list can exploit this issue, via a vulnerable script shipped with the
product, to gain root privileges by using a 'su root' action.");
  script_set_attribute(attribute:"see_also", value:"http://aix.software.ibm.com/aix/efixes/security/powerha_advisory.asc");
  script_set_attribute(attribute:"solution", value:
"Install the appropriate interim fix according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:6.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:7.1");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"AIX Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("aix.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if ( ! get_kb_item("Host/AIX/version") ) audit(AUDIT_OS_NOT, "AIX");
if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

if ( get_kb_item("Host/AIX/emgr_failure" ) ) exit(0, "This iFix check is disabled because : "+get_kb_item("Host/AIX/emgr_failure") );

flag = 0;

ifixes_61 = "(IV76943|IV76943_61|IV77007m0a)";
ifixes_712 = "(IV76943|IV76943712)";
ifixes_713 = "(IV76943|IV76943713|IV77444s0a)";
if (aix_check_ifix(release:"6.1", ml:"00", patch:ifixes_61, package:"cluster.es.client.rte", minfilesetver:"6.1.0.0", maxfilesetver:"6.1.0.11") < 0) flag++;
if (aix_check_ifix(release:"6.1", ml:"00", patch:ifixes_61, package:"cluster.es.cspoc.cmds", minfilesetver:"6.1.0.0", maxfilesetver:"6.1.0.15") < 0) flag++;
if (aix_check_ifix(release:"6.1", ml:"00", patch:ifixes_61, package:"cluster.es.cspoc.rte", minfilesetver:"6.1.0.0", maxfilesetver:"6.1.0.14") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"02", patch:ifixes_712, package:"cluster.es.client.rte", minfilesetver:"7.1.2.0", maxfilesetver:"7.1.2.3") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"02", patch:ifixes_712, package:"cluster.es.cspoc.cmds", minfilesetver:"7.1.2.0", maxfilesetver:"7.1.2.6") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"02", patch:ifixes_712, package:"cluster.es.cspoc.rte", minfilesetver:"7.1.2.0", maxfilesetver:"7.1.2.6") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"03", patch:ifixes_713, package:"cluster.es.client.rte", minfilesetver:"7.1.3.0", maxfilesetver:"7.1.3.2") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"03", patch:ifixes_713, package:"cluster.es.cspoc.cmds", minfilesetver:"7.1.3.0", maxfilesetver:"7.1.3.3") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"03", patch:ifixes_713, package:"cluster.es.cspoc.rte", minfilesetver:"7.1.3.0", maxfilesetver:"7.1.3.3") < 0) flag++;

if (flag)
{
  aix_report_extra = ereg_replace(string:aix_report_get(), pattern:"[()]", replace:"");
  aix_report_extra = ereg_replace(string:aix_report_extra, pattern:"[|]", replace:" or ");
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : aix_report_extra
  );
}
else
{
  tested = aix_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cluster.es.client.rte / cluster.es.cspoc.cmds / cluster.es.cspoc.rte");
}
