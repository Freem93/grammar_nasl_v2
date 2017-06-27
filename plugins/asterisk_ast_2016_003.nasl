#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88715);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/11/11 20:08:42 $");

  script_cve_id("CVE-2011-3389");
  script_bugtraq_id(
    49778,
    82651,
    82656,
    82670
  );
  script_osvdb_id(
    74829,
    113947,
    134040,
    134041
  );
  script_xref(name:"CERT", value:"864643");

  script_name(english:"Asterisk Multiple Vulnerabilities (AST-2016-001 - AST-2016-003) (BEAST)");
  script_summary(english:"Checks the version in the SIP banner.");

  script_set_attribute(attribute:"synopsis", value:
"A telephony application running on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its SIP banner, the version of Asterisk running on the
remote host is affected by the following vulnerabilities :

  - An information disclosure vulnerability, known as BEAST,
    exists in the SSL 3.0 and TLS 1.0 protocols due to a
    flaw in the way the initialization vector (IV) is
    selected when operating in cipher-block chaining (CBC)
    modes. A man-in-the-middle attacker can exploit this
    to obtain plaintext HTTP header data, by using a
    blockwise chosen-boundary attack (BCBA) on an HTTPS
    session, in conjunction with JavaScript code that uses
    the HTML5 WebSocket API, the Java URLConnection API,
    or the Silverlight WebClient API. (CVE-2011-3389)

  - An integer overflow condition exists in sip.conf due to
    improper validation of user-supplied input when handling
    'timert1' values. A remote attacker can exploit this to
    cause a denial of service. (VulnDB 134040)

  - An unspecified flaw exists due to improper handling of
    FAT data in UDPTL packets. A remote attacker can exploit
    this to cause a denial of service. (VulnDB 134041)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Asterisk version 11.21.1 / 13.7.1 / 11.6-cert12 /
13.1-cert3. Alternatively, apply the appropriate patch referenced in
the vendor advisories.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"see_also", value:"http://downloads.asterisk.org/pub/security/AST-2016-001.html");
  script_set_attribute(attribute:"see_also", value:"http://downloads.asterisk.org/pub/security/AST-2016-002.html");
  script_set_attribute(attribute:"see_also", value:"http://downloads.asterisk.org/pub/security/AST-2016-003.html");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2011/09/23/chromeandbeast.html");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:digium:asterisk");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("asterisk_detection.nasl");
  script_require_keys("asterisk/sip_detected", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("asterisk/sip_detected");

asterisk_kbs = get_kb_list_or_exit("sip/asterisk/*/version");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

is_vuln = FALSE;
not_vuln_installs = make_list();
errors = make_list();

foreach kb_name (keys(asterisk_kbs))
{
  vulnerable = 0;
  patch_only = FALSE;

  matches = eregmatch(pattern:"/(udp|tcp)/([0-9]+)/version", string:kb_name);
  if (isnull(matches))
  {
    errors = make_list(errors, "Unexpected error parsing port number from '"+kb_name+"'.");
    continue;
  }

  proto = matches[1];
  port  = matches[2];
  version = asterisk_kbs[kb_name];

  if (version == 'unknown')
  {
    errors = make_list(errors, "Unable to obtain version of install on " + proto + "/" + port + ".");
    continue;
  }

  banner = get_kb_item("sip/asterisk/" + proto + "/" + port + "/source");
  if (!banner)
  {
    # We have version but banner is missing;
    # log error and use in version-check though.
    errors = make_list(errors, "KB item 'sip/asterisk/" + proto + "/" + port + "/source' is missing.");
    banner = 'unknown';
  }

  # Open Source 1.8.x
  # Patch does not change version.
  if (version =~ "^1\.8([^0-9]|$)" && "cert" >!< tolower(version))
  {
    fixed = "See vendor for patch information.";
    patch_only = TRUE;
  }

  # Open Source 11.x
  if (version =~ "^11([^0-9]|$)" && "cert" >!< tolower(version))
  {
    fixed = "11.21.1";
    vulnerable = ver_compare(ver:version, fix:fixed, app:"asterisk");
  }

  # Open Source 12.x
  # Patch does not change version
  else if (version =~ "^12([^0-9]|$)" && "cert" >!< tolower(version))
  {
    fixed = "See vendor for patch information.";
    patch_only = TRUE;
  }

  # Open Source 13.x
  else if (version =~ "^13([^0-9]|$)" && "cert" >!< tolower(version))
  {
    fixed = "13.7.1";
    vulnerable = ver_compare(ver:version, fix:fixed, app:"asterisk");
  }

  # Asterisk Certified 1.8.28-certx
  # Patch does not change version.
  else if (version =~ "^1\.8\.28([^0-9])" && "cert" >< tolower(version))
  {
    fixed = "See vendor for patch information.";
    patch_only = TRUE;
  }

  # Asterisk Certified 11.6-certx
  else if (version =~ "^11\.6([^0-9])" && "cert" >< tolower(version))
  {
    fixed = "11.6-cert12";
    vulnerable = ver_compare(ver:version, fix:fixed, app:"asterisk");
  }

  # Asterisk Certified 13.1-certx < 13.1-cert2
  else if (version =~ "^13\.1([^0-9])" && "cert" >< tolower(version))
  {
    fixed = "13.1-cert3";
    vulnerable = ver_compare(ver:version, fix:fixed, app:"asterisk");
  }

  if (vulnerable < 0 || patch_only == TRUE)
  {
    is_vuln = TRUE;
    if (report_verbosity > 0)
    {
      report =
        '\n  Version source    : ' + banner +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fixed +
        '\n';
      security_hole(port:port, proto:proto, extra:report);
    }
    else security_hole(port:port, proto:proto);
  }
  else not_vuln_installs = make_list(not_vuln_installs, version + " on port " + proto + "/" + port);
}

if (max_index(errors))
{
  if (max_index(errors) == 1) errmsg = errors[0];
  else errmsg = 'Errors were encountered verifying installs : \n  ' + join(errors, sep:'\n  ');

  exit(1, errmsg);
}
else
{
  installs = max_index(not_vuln_installs);
  if (installs == 0)
  {
    if (is_vuln) exit(0);
    else audit(AUDIT_NOT_INST, "Asterisk");
  }
  else audit(AUDIT_INST_VER_NOT_VULN, "Asterisk", not_vuln_installs);
}
