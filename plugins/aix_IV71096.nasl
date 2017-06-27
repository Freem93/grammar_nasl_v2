#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory ntp4_advisory.asc.
#

include("compat.inc");

if (description)
{
  script_id(84493);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/01/22 14:36:50 $");

  script_cve_id("CVE-2014-9297", "CVE-2015-1799");

  script_name(english:"AIX 7.1 TL 0 : ntp4 (IV71096)");
  script_summary(english:"Check for APAR IV71096");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote AIX host is missing a security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-9297 Network
Time Protocol (NTP) Project NTP daemon (ntpd) could allow a remote
attacker to conduct spoofing attacks, caused by insufficient entropy
in PRNG. An attacker could exploit this vulnerability to spoof the
IPv6 address ::1 to bypass ACLs and launch further attacks on the
system. Network Time Protocol (NTP) Project NTP daemon (ntpd) is
vulnerable to a denial of service, caused by an error when using
symmetric key authentication. By sending specially-crafted packets to
both peering hosts, an attacker could exploit this vulnerability to
prevent synchronization."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aix.software.ibm.com/aix/efixes/security/ntp4_advisory.asc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install the appropriate interim fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:7.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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

if (aix_check_ifix(release:"7.1", ml:"00", patch:"IV71096s0a", package:"ntp.rte", minfilesetver:"7.1.0.0", maxfilesetver:"7.1.0.4") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:aix_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
