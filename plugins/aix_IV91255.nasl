#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory bind_advisory14.asc.
#

include("compat.inc");

if (description)
{
  script_id(95892);
  script_version("$Revision: 3.7 $");
  script_cvs_date("$Date: 2017/01/23 17:47:50 $");

  script_cve_id("CVE-2016-2848", "CVE-2016-8864");

  script_name(english:"AIX 7.1 TL 4 : bind (IV91255)");
  script_summary(english:"Check for APAR IV91255");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote AIX host is missing a security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-8864
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-8864 ISC BIND
is vulnerable to a denial of service, caused by the improper handling
of responses containing a DNAME answer in db.c or resolver.c. By
sending a recursive response, a remote attacker could exploit this
vulnerability to trigger an assertion failure. ISC BIND is vulnerable
to a denial of service. By sending a specially crafted DNS packet with
malformed options, a remote attacker could exploit this vulnerability
to trigger an assertion failure."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aix.software.ibm.com/aix/efixes/security/bind_advisory14.asc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the appropriate interim fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:7.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/16");
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

if (aix_check_ifix(release:"7.1", ml:"04", sp:"01", patch:"IV91255m1b", package:"bos.net.tcp.client", minfilesetver:"7.1.4.0", maxfilesetver:"7.1.4.30") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"04", sp:"02", patch:"IV91255m2a", package:"bos.net.tcp.client", minfilesetver:"7.1.4.0", maxfilesetver:"7.1.4.30") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"04", sp:"03", patch:"IV91255m3c", package:"bos.net.tcp.client", minfilesetver:"7.1.4.0", maxfilesetver:"7.1.4.30") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:aix_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
