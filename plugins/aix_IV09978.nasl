#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory bind9_advisory3.asc.
#

include("compat.inc");

if (description)
{
  script_id(63700);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/12/17 15:40:22 $");

  script_cve_id("CVE-2009-0025", "CVE-2010-0097", "CVE-2010-0382", "CVE-2011-4313");
  script_bugtraq_id(33151, 37118, 37865);

  script_name(english:"AIX 6.1 TL 7 : bind9 (IV09978)");
  script_summary(english:"Check for APAR IV09978");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote AIX host is missing a security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An as-yet unidentified network event caused BIND 9 resolvers to cache
an invalid record, subsequent queries for which could crash the
resolvers with an assertion failure.

Furthermore, AIX BIND 9.4.1 is affected by the following three
security vulnerabilities: CVE-2010-0382 - ISC BIND Out-Of-Bailwick
Data Handling Error CVE-2010-0097 - ISC BIND Improper DNSSEC NSEC and
NSEC3 Record CVE-2009-0025 - BIND OpenSSL DSA_do_verify and
EVP_VerifyFinal."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.isc.org/software/bind/advisories/cve-2011-4313"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aix.software.ibm.com/aix/efixes/security/bind9_advisory3.asc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the appropriate interim fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:6.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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

if (aix_check_ifix(release:"6.1", ml:"07", sp:"01", patch:"IV09978m01", package:"bos.net.tcp.client", minfilesetver:"6.1.7.0", maxfilesetver:"6.1.7.1") < 0) flag++;
if (aix_check_ifix(release:"6.1", ml:"07", sp:"01", patch:"IV09978m01", package:"bos.net.tcp.server", minfilesetver:"6.1.7.0", maxfilesetver:"6.1.7.0") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:aix_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
