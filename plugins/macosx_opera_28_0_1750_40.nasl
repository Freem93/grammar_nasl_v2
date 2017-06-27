#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81882);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/16 14:02:53 $");

  script_cve_id("CVE-2015-0204");
  script_bugtraq_id(71936);
  script_osvdb_id(116794, 119307);
  script_xref(name:"CERT", value:"243585");

  script_name(english:"Opera < 28.0.1750.40 SSL/TLS EXPORT_RSA Ciphers Downgrade MitM (Mac OS X) (FREAK)");
  script_summary(english:"Checks the version of Opera browser.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host has a web browser installed that is affected
by the FREAK vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host has a version of the Opera web browser
installed that is prior to 28.0.1750.40. It is, therefore, affected by
a security feature bypass vulnerability, known as FREAK (Factoring
attack on RSA-EXPORT Keys), due to the support of weak EXPORT_RSA
cipher suites with keys less than or equal to 512 bits. A
man-in-the-middle attacker may be able to downgrade the SSL/TLS
connection to use EXPORT_RSA cipher suites which can be factored in a
short amount of time, allowing the attacker to intercept and decrypt
the traffic.");
  script_set_attribute(attribute:"see_also", value:"https://www.smacktls.com/#freak");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/docs/changelogs/unified/2800/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Opera version 28.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:opera:opera_browser");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_opera_installed.nbin");
  script_require_keys("installed_sw/Opera");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

app = "Opera";

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
path    = install['path'];
version = install['version'];

fix = '28.0.1750.40';
if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app, version);
