#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory bind_advisory11.asc.
#

include("compat.inc");

if (description)
{
  script_id(90717);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/07 15:17:40 $");

  script_cve_id("CVE-2015-8704");

  script_name(english:"AIX 6.1 TL 9 : bind (IV81279)");
  script_summary(english:"Check for APAR IV81279");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote AIX host is missing a security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"ISC BIND is vulnerable to a denial of service, caused by improper
bounds checking in apl_42.c. By sending specially crafted Address
Prefix List (APL) data, a remote authenticated attacker could exploit
this vulnerability to trigger an INSIST assertion failure and cause
the named process to terminate."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aix.software.ibm.com/aix/efixes/security/bind_advisory11.asc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the appropriate interim fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:6.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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

if (aix_check_ifix(release:"6.1", ml:"09", sp:"04", patch:"IV81279m4c", package:"bos.net.tcp.client", minfilesetver:"6.1.9.0", maxfilesetver:"6.1.9.101") < 0) flag++;
if (aix_check_ifix(release:"6.1", ml:"09", sp:"05", patch:"IV81279m5a", package:"bos.net.tcp.client", minfilesetver:"6.1.9.0", maxfilesetver:"6.1.9.101") < 0) flag++;
if (aix_check_ifix(release:"6.1", ml:"09", sp:"06", patch:"IV81279s6a", package:"bos.net.tcp.client", minfilesetver:"6.1.9.0", maxfilesetver:"6.1.9.101") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:aix_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
