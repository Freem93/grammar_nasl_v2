#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory bind9_advisory7.asc.
#

include("compat.inc");

if (description)
{
  script_id(81498);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/03/11 13:51:23 $");

  script_cve_id("CVE-2014-8500");
  script_bugtraq_id(71590);

  script_name(english:"AIX 6.1 TL 8 : bind9 (IV68993)");
  script_summary(english:"Check for APAR IV68993");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote AIX host is missing a security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2014-8500 ISC BIND 9.0.x through 9.8.x, 9.9.0 through 9.9.6, and
9.10.0 through 9.10.1 does not limit delegation chaining, which allows
remote attackers to cause a denial of service (memory consumption and
named crash) via a large or infinite number of referrals. 

Please see following for more information :

http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-8500"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aix.software.ibm.com/aix/efixes/security/bind9_advisory7.asc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the appropriate interim fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:6.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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

if (aix_check_ifix(release:"6.1", ml:"08", sp:"06", patch:"IV68993s6a", package:"bos.net.tcp.server", minfilesetver:"6.1.8.0", maxfilesetver:"6.1.8.18") < 0) flag++;
if (aix_check_ifix(release:"6.1", ml:"08", sp:"06", patch:"IV68993s6a", package:"bos.net.tcp.client", minfilesetver:"6.1.8.0", maxfilesetver:"6.1.8.19") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:aix_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
