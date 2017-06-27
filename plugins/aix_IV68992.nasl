#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory tcpdump_advisory.asc.
#

include("compat.inc");

if (description)
{
  script_id(81923);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/03/19 15:24:54 $");

  script_cve_id("CVE-2014-8769");

  script_name(english:"AIX 6.1 TL 9 : tcpdump (IV68992)");
  script_summary(english:"Check for APAR IV68992");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote AIX host is missing a security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2014-8769 tcpdump is vulnerable to a denial of service, caused by
the improper handling of input by the application decoder for the Ad
hoc On-Demand Distance Vector (AODV) protocol. By sending
specially-crafted data, a remote attacker could exploit this
vulnerability to cause the application to crash.

Please see following for more information :

http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-8769"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aix.software.ibm.com/aix/efixes/security/tcpdump_advisory.asc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the appropriate interim fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:6.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/19");
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

if (aix_check_ifix(release:"6.1", ml:"09", sp:"04", patch:"IV68992s4a", package:"bos.net.tcp.server", minfilesetver:"6.1.9.0", maxfilesetver:"6.1.9.30") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:aix_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
