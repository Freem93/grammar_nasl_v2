#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory lquerylv_advisory.asc.
#

include("compat.inc");

if (description)
{
  script_id(94442);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2017/02/21 14:37:31 $");

  script_cve_id("CVE-2016-6079");

  script_name(english:"AIX 7.1 TL 4 : lquerylv (IV87640)");
  script_summary(english:"Check for APAR IV87640");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote AIX host is missing a security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-6079
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-6079 AIX
contains an unspecified vulnerability that would allow a locally
authenticated user to obtain root level privileges."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aix.software.ibm.com/aix/efixes/security/lquerylv_advisory.asc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the appropriate interim fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:7.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
  script_family(english:"AIX Local Security Checks");

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

if (aix_check_ifix(release:"7.1", ml:"04", sp:"00", patch:"IV87640s2a", package:"bos.rte.lvm", minfilesetver:"7.1.4.0", maxfilesetver:"7.1.4.1") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"04", sp:"01", patch:"IV87640s2a", package:"bos.rte.lvm", minfilesetver:"7.1.4.0", maxfilesetver:"7.1.4.1") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"04", sp:"02", patch:"IV87640s2a", package:"bos.rte.lvm", minfilesetver:"7.1.4.0", maxfilesetver:"7.1.4.1") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:aix_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
