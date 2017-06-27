#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory perl_advisory2.asc.
#

include("compat.inc");

if (description)
{
  script_id(64299);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/03/11 18:51:57 $");

  script_cve_id("CVE-2011-3597");

  script_name(english:"AIX 5.3 TL 12 : perl (IV10197)");
  script_summary(english:"Check for APAR IV10197");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote AIX host is missing a security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Digest module for Perl is prone to a vulnerability that will let
attackers inject and execute arbitrary Perl code.

Remote attackers can exploit this issue to run arbitrary code in the
context of the affected application.

Digest versions prior to 1.17 are affected.

For more details please visit :

http://www.securityfocus.com/bid/49911
https://secunia.com/advisories/46279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aix.software.ibm.com/aix/efixes/security/perl_advisory2.asc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the appropriate interim fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:5.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/11/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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

if (aix_check_ifix(release:"5.3", ml:"12", patch:"IV10197610", package:"5.3.12", minfilesetver:"5.8.8.0", maxfilesetver:"5.8.8.122") < 0) flag++;
if (aix_check_ifix(release:"6.1", ml:"05", patch:"IV10197610", package:"6.1.5", minfilesetver:"5.8.8.0", maxfilesetver:"5.8.8.122") < 0) flag++;
if (aix_check_ifix(release:"6.1", ml:"06", patch:"IV10197610", package:"6.1.6", minfilesetver:"5.8.8.0", maxfilesetver:"5.8.8.122") < 0) flag++;
if (aix_check_ifix(release:"6.1", ml:"07", patch:"IV10197610", package:"6.1.7", minfilesetver:"5.8.8.0", maxfilesetver:"5.8.8.122") < 0) flag++;
if (aix_check_ifix(release:"6.1", ml:"08", patch:"IV10197610", package:"6.1.8", minfilesetver:"5.8.8.0", maxfilesetver:"5.8.8.122") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"00", patch:"IV10197710", package:"7.1.0", minfilesetver:"5.10.1.0", maxfilesetver:"5.10.1.50") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"01", patch:"IV10197710", package:"7.1.1", minfilesetver:"5.10.1.0", maxfilesetver:"5.10.1.50") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"02", patch:"IV10197710", package:"7.1.2", minfilesetver:"5.10.1.0", maxfilesetver:"5.10.1.50") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:aix_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
