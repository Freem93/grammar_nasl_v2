#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory bind9_advisory5.asc.
#

include("compat.inc");

if (description)
{
  script_id(63748);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/03/11 18:51:58 $");

  script_cve_id("CVE-2012-5166");

  script_name(english:"AIX 7.1 TL 1 : bind9 (IV30367)");
  script_summary(english:"Check for APAR IV30367");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote AIX host is missing a security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"If specific combinations of RDATA are loaded into a nameserver, either
via cache or an authoritative zone, a subsequent query for a related
record will cause named to lock up."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aix.software.ibm.com/aix/efixes/security/bind9_advisory5.asc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the appropriate interim fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:7.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
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

if (aix_check_ifix(release:"7.1", ml:"01", sp:"05", patch:"IV30367s05", package:"bos.net.tcp.client", minfilesetver:"7.1.1.0", maxfilesetver:"7.1.1.17") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"01", sp:"05", patch:"IV30367s05", package:"bos.net.tcp.server", minfilesetver:"7.1.1.0", maxfilesetver:"7.1.1.17") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"01", sp:"06", patch:"IV30367s06", package:"bos.net.tcp.client", minfilesetver:"7.1.1.0", maxfilesetver:"7.1.1.17") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"01", sp:"06", patch:"IV30367s06", package:"bos.net.tcp.server", minfilesetver:"7.1.1.0", maxfilesetver:"7.1.1.17") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:aix_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
