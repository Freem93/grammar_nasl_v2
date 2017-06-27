#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80479);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/14 15:47:37 $");

  script_cve_id("CVE-2014-0076", "CVE-2014-0963");
  script_bugtraq_id(66363, 67238);
  script_osvdb_id(104810, 106786);

  script_name(english:"IBM Tivoli Access Manager for e-Business < 6.0.0.33 / 6.1.0.14 / 6.1.1.10 SSL Multiple Vulnerabilities");
  script_summary(english:"Checks the Runtime component version.");

  script_set_attribute(attribute:"synopsis", value:
"An access and authorization control management system installed on the
remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the install of the IBM Tivoli
Access Manager for e-Business is affected by multiple vulnerabilities
:

  - An error exists related to the implementation of the
    Elliptic Curve Digital Signature Algorithm (ECDSA) that
    allows nonce disclosure via the 'FLUSH+RELOAD' cache
    side-channel attack. (CVE-2014-0076)

  - A denial of service vulnerability exists that allows an
    attacker, using a specially crafted SSL request, to
    cause the host to become unresponsive. Note that this
    issue only affects the WebSEAL component and a
    workaround is available. (CVE-2014-0963)");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21672950");
  script_set_attribute(attribute:"see_also", value:"http://www.ibm.com/support/docview.wss?uid=swg21673008");
  script_set_attribute(attribute:"solution", value:
"Apply the interim fix 6.0.0-ISS-TAM-IF0033 / 6.1.0-ISS-TAM-IF0014 /
6.1.1-ISS-TAM-IF0010 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_access_manager_for_e-business");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("tivoli_access_manager_ebiz_installed_components_cred.nasl");
  script_require_keys("installed_sw/IBM Access Manager for e-Business / IBM Security Access Manager");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app     = 'IBM Access Manager for e-Business / IBM Security Access Manager';
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

ver    = install['version'];
fix    = NULL;
no_fix = FALSE;

# Affected :
# 5.1.0.x (no longer supported)
# 6.0.0.x < 6.0.0.33
# 6.1.0.x < 6.1.0.14
# 6.1.1.x < 6.1.1.10
if (ver =~ "^5\.1\.0([^0-9]|$)")
{
  fix = "Refer to the advisory.";
  no_fix = TRUE;
}
else if (ver =~ "^6\.0\.0\.")
  fix = "6.0.0.33";
else if (ver =~ "^6\.1\.0\.")
  fix = "6.1.0.14";
else if (ver =~ "^6\.1\.1\.")
  fix = "6.1.1.10";
else
  audit(AUDIT_NOT_INST, app + " ver 5.1.0.x / 6.0.0.x / 6.1.0.x / 6.1.1.x");

if (no_fix || ver_compare(ver:ver, fix:fix, strict:FALSE) < 0)
{
  port = 0;

  if (report_verbosity > 0)
  {
    report =
      '\n' +
      '\n    Installed version : ' + ver +
      '\n    Fixed version     : ' + fix +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_VER_NOT_VULN, app, ver);
