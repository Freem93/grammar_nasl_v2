#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory ssl_advisory.asc.
#

include("compat.inc");

if (description)
{
  script_id(73566);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/19 17:45:32 $");

  script_cve_id("CVE-2009-3555");
  script_bugtraq_id(36935);
  script_osvdb_id(59971);
  script_xref(name:"CERT", value:"120541");
  script_xref(name:"EDB-ID", value:"9972");

  script_name(english:"AIX OpenSSL Advisory : ssl_advisory.asc");
  script_summary(english:"Checks the version of the openssl packages");

  script_set_attribute(attribute:"synopsis", value:"The remote AIX host is running a vulnerable version of OpenSSL.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL running on the remote host is affected by the
following vulnerabilities :

  - A vulnerability in the way SSL and TLS protocols allow
    renegotiation requests may allow an attacker to inject
    plaintext into an application protocol stream. This
    could result in a situation where the attacker may be
    able to issue commands to the server that appear to be
    coming from a legitimate source.

  - A remote, unauthenticated attacker may be able to inject
    an arbitrary amount of chosen plaintext into the
    beginning of the application protocol stream. This could
    allow an attacker to issue HTTP requests or take action
    impersonating the user, among other consequences.

Please note that the recommended fixes will disable all session
renegotiation.");
  script_set_attribute(attribute:"see_also", value:"http://aix.software.ibm.com/aix/efixes/security/ssl_advisory.asc");
  script_set_attribute(attribute:"see_also", value:"https://www14.software.ibm.com/webapp/iwm/web/preLogin.do?source=aixbp");
  script_set_attribute(attribute:"solution", value:
"A fix is available, and it can be downloaded from the AIX website.

To extract the fixes from the tar file :

  zcat openssl.0.9.8.1102.tar.Z | tar xvf -
  or
  zcat openssl-fips.12.9.8.1102.tar.Z | tar xvf -
  or
  zcat openssl.0.9.8.805.tar.Z | tar xvf -

IMPORTANT : If possible, it is recommended that a mksysb backup of
the system be created.  Verify it is both bootable and readable
before proceeding.

To preview the fix installation :

  installp -apYd . openssl

To install the fix package :

  installp -aXYd . openssl");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/16");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
  script_family(english:"AIX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version");

  exit(0);
}


include("aix.inc");
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
oslevel = get_kb_item_or_exit("Host/AIX/version");
if ( oslevel != "AIX-5.2" && oslevel != "AIX-5.3" && oslevel != "AIX-6.1" )
{
  oslevel = ereg_replace(string:oslevel, pattern:"-", replace:" ");
  audit(AUDIT_OS_NOT, "AIX 5.2 / 5.3 / 6.1", oslevel);
}
if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

flag = 0;

if (aix_check_package(release:"5.2", package:"openssl.base", minpackagever:"0.0.0.0", maxpackagever:"0.9.8.804", fixpackagever:"0.9.8.805") > 0) flag++;
if (aix_check_package(release:"5.3", package:"openssl.base", minpackagever:"0.0.0.0", maxpackagever:"0.9.8.1101", fixpackagever:"0.9.8.1102") > 0) flag++;
if (aix_check_package(release:"6.1", package:"openssl.base", minpackagever:"0.0.0.0", maxpackagever:"0.9.8.1101", fixpackagever:"0.9.8.1102") > 0) flag++;
if (aix_check_package(release:"5.3", package:"openssl-fips.base", minpackagever:"0.0.0.0", maxpackagever:"12.9.8.1101", fixpackagever:"12.9.8.1102") > 0) flag++;
if (aix_check_package(release:"6.1", package:"openssl-fips.base", minpackagever:"0.0.0.0", maxpackagever:"12.9.8.1101", fixpackagever:"12.9.8.1102") > 0) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : aix_report_get()
  );
}
else
{
  tested = aix_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl.base / openssl-fips.base");
}
