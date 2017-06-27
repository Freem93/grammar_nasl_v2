#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69079);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/03/28 20:29:26 $");

  script_cve_id("CVE-2013-3384", "CVE-2013-3385", "CVE-2013-3386");
  script_bugtraq_id(60805, 60806, 60807);
  script_osvdb_id(94604, 94605, 94609);
  script_xref(name:"CISCO-BUG-ID", value:"CSCzv24579");
  script_xref(name:"CISCO-BUG-ID", value:"CSCzv78669");
  script_xref(name:"CISCO-BUG-ID", value:"CSCzv81712");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130626-sma");

  script_name(english:"Multiple Vulnerabilities in Cisco Content Security Management Appliance (cisco-sa-20130626-sma)");
  script_summary(english:"Checks SMA version");

  script_set_attribute(attribute:"synopsis", value:"The remote security appliance is missing a vendor-supplied patch.");
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version, the version of Cisco Content
Security Management Appliance running on the remote host has the
following vulnerabilities :

  - An unspecified vulnerability exists in the web framework
    that could allow a remote, authenticated attacker to
    execute arbitrary commands. (CVE-2013-3384)

  - A denial of service vulnerability exists in the web
    framework that could allow a remote, unauthenticated
    attacker to make the system unresponsive.
    (CVE-2013-3385)

  - A denial of service vulnerability exists in the
    management GUI that could allow a remote,
    unauthenticated attacker to make the system
    unresponsive. (CVE-2013-3386)"
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130626-sma
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dab68fde");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant update referenced in Cisco Security Advisory
cisco-sa-20130626-sma."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:content_security_management_appliance");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("cisco_sma_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Content Security Management Appliance/DisplayVersion", "Host/AsyncOS/Cisco Content Security Management Appliance/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

display_ver = get_kb_item_or_exit('Host/AsyncOS/Cisco Content Security Management Appliance/DisplayVersion');
ver = get_kb_item_or_exit('Host/AsyncOS/Cisco Content Security Management Appliance/Version');

if (ver =~ "^[0-6]\." || ver =~ "^7\.[012]\.") # 7.2 and earlier
  display_fix = '7.9.1-102';
else if (ver =~ "^7\.7\.")
  display_fix = '7.9.1-102';
else if (ver =~ "^7\.8\.")
  display_fix = '7.9.1-102';
else if (ver =~ "^7\.9\.")
  display_fix = '7.9.1-102';
else if (ver =~ "^8\.0\.")
  display_fix = '8.0.0-404';
else
  audit(AUDIT_INST_VER_NOT_VULN, 'Cisco SMA', display_ver);

fix = str_replace(string:display_fix, find:'-', replace:'.');

if (ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'Cisco SMA', display_ver);

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + display_ver +
    '\n  Fixed version     : ' + display_fix + '\n';
  security_hole(port:0, extra:report);
}
else security_hole(0);

