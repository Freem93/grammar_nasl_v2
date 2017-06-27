#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory openssh_advisory.asc.
#

include("compat.inc");

if (description)
{
  script_id(73557);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/04/25 14:28:28 $");

  script_cve_id("CVE-2008-3259", "CVE-2008-5161");
  script_bugtraq_id(30339, 32319);
  script_osvdb_id(47227, 50036);
  script_xref(name:"CERT", value:"958563");

  script_name(english:"AIX OpenSSH Advisory: openssh_advisory.asc");
  script_summary(english:"Checks the version of the openssh client and server packages");

  script_set_attribute(attribute:"synopsis", value:"The remote AIX host is running a vulnerable version of OpenSSH.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSH running on the remote host is affected by the
following vulnerabilities :

  - X11 man-in-the-middle attack:
    When attempting to bind(2) to a port that has previously
    been bound with SO_REUSEADDR set, most operating systems
    check that either the effective user-id matches the
    previous bind (common on BSD-derived systems) or that
    the bind addresses do not overlap. When the
    sshd_config(5) option X11UseLocalhost has been set to
    'no' - an attacker may establish a more-specific bind,
    which will be used in preference to sshd's wildcard
    listener. (CVE-2008-3259)

  - Plaintext Recovery Attack Against SSH:
    If exploited, this attack can potentially allow an
    attacker to recover up to 32 bits of plaintext from an
    arbitrary block of ciphertext from a connection secured
    using the SSH protocol in the standard configuration.
    If OpenSSH is used in the standard configuration, then
    the attacker's success probability for recovering 32
    bits of plaintext is 2^{-18}. A variant of the attack
    against OpenSSH in the standard configuration can
    verifiably recover 14 bits of plaintext with probability
    2^{-14}. The success probability of the attack for other
    implementations of SSH is not known. (CVE-2008-5161)");
  script_set_attribute(attribute:"see_also", value:"http://aix.software.ibm.com/aix/efixes/security/openssh_advisory.asc");
  script_set_attribute(attribute:"see_also", value:"http://www.openssh.org/txt/cbc.adv");
  script_set_attribute(attribute:"see_also", value:"http://www.openssh.com/txt/release-5.1");
  script_set_attribute(attribute:"see_also", value:"https://sourceforge.net/projects/openssh-aix/files/");
  script_set_attribute(attribute:"solution", value:
"A fix is available for AIX versions 5.3 and 6.1, and it can be
downloaded from the OpenSSH sourceforge website for the AIX release.
There is no fix for AIX version 5.2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/07/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/16");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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

if (aix_check_package(release:"5.2", package:"openssh.base.client", minpackagever:"0.0.0.0", maxpackagever:"6.0.0.0", fixpackagever:"Special") > 0) flag++;
if (aix_check_package(release:"5.2", package:"openssh.base.server", minpackagever:"0.0.0.0", maxpackagever:"6.0.0.0", fixpackagever:"Special") > 0) flag++;
if (aix_check_package(release:"5.3", package:"openssh.base.client", minpackagever:"0.0.0.0", maxpackagever:"5.2.0.5299", fixpackagever:"5.2.0.5300") > 0) flag++;
if (aix_check_package(release:"5.3", package:"openssh.base.server", minpackagever:"0.0.0.0", maxpackagever:"5.2.0.5299", fixpackagever:"5.2.0.5300") > 0) flag++;
if (aix_check_package(release:"6.1", package:"openssh.base.client", minpackagever:"0.0.0.0", maxpackagever:"5.2.0.5299", fixpackagever:"5.2.0.5300") > 0) flag++;
if (aix_check_package(release:"6.1", package:"openssh.base.server", minpackagever:"0.0.0.0", maxpackagever:"5.2.0.5299", fixpackagever:"5.2.0.5300") > 0) flag++;

if (flag)
{
  # Disassemble and reassemble aix_report_get(), the 5.2 version has no fix and requires special reporting
  curr_report = aix_report_get();
  lines = split(curr_report, sep:'\n', keep:0);
  new_report = "";
  foreach currline (lines)
  {
    new_line = ereg_replace(string:currline, pattern:"Should be : openssh\.base\.(client|server)\.Special", replace:"OpenSSH on AIX version 5.2 has no fix for this issue.");
    new_report += new_line + '\n';
  }
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : new_report
  );
}
else
{
  tested = aix_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh.base.client / openssh.base.server");
}
