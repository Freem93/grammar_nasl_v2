#TRUSTED 7b1cbcbb5961f93fc28efaab01873924bfc7dd1a1799d33e17a257c1efcc7812f7842057c7ffb7ee69a24d4faf236aae4aea8fb868f9607b359cb72313204b67fa25b2f715a5a5058c9e79bf16dadd8e933e780b21ea7777be123c34de81b49cffcb398ed254be0c99fb6cc1690a779d809f9278800bf4c85137573189129a607233d47b02fc9d65aa5dbf7e6c42bdec6a536e4a1eb3815ac64274f3d5004b7047d4ca19f05f6914bea359066ab6dfdc40548c81e2c3c94f95864d6113a1775a9fbc57b770908865050df387caa1aa801938ffca6c99c94dfa321ced279aa002a42fb4edc0c97864462926661cf7ce8f4c3846a95777d514bad09a62f292599ffac5de67283a59e131d89adb2de130cb7d34996bd1bdcac5a34f015334170b2b971a144d0eda630008be64bc9e7ef24e162290533186b81c74994b9d87091454871710884fb1d7a6a36db7d9637be8378c4a1a8d46d170b581d8f97db9c23ca0ed3ef5e8d2c520bcfa8603f9c054e40e58b98fdd4830e1bb49a5c2f0631404449731bd2078da3fc6eb3c1ebe2da1db1e4882a34a6c9161dcc8ab13258f756cb4601bd776ecc649f63c93e9c7914ba89a76be606d7cc4ef6ce73aa93bc71a4140f513a18b39e740894479f96de2220625deaa0e6a773f1610e305ba39cbe220c1d3dfcdeee02534b432ff3174830a7d4601f20f8ba43ab2142a3e1a89987df84d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77000);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id(
    "CVE-2010-5298",
    "CVE-2014-0198",
    "CVE-2014-0224",
    "CVE-2014-3470"
  );
  script_bugtraq_id(66801, 67193, 67898, 67899);
  script_osvdb_id(105763, 106531, 107729, 107731);
  script_xref(name:"CERT", value:"978508");
  script_xref(name:"JSA", value:"JSA10629");

  script_name(english:"Juniper Junos Multiple OpenSSL Vulnerabilities (JSA10629)");
  script_summary(english:"Checks the Junos version and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by the following vulnerabilities related to
OpenSSL :

  - An error exists in the ssl3_read_bytes() function
    that permits data to be injected into other sessions
    or allows denial of service attacks. Note that this
    issue is exploitable only if SSL_MODE_RELEASE_BUFFERS
    is enabled. (CVE-2010-5298)

  - An error exists in the do_ssl3_write() function that
    permits a NULL pointer to be dereferenced, which could
    allow denial of service attacks. Note that this issue
    is exploitable only if SSL_MODE_RELEASE_BUFFERS is
    enabled. (CVE-2014-0198)

  - An error exists in the processing of ChangeCipherSpec
    messages that allows the usage of weak keying material.
    This permits simplified man-in-the-middle attacks to be
    done. (CVE-2014-0224)

  - An error exists in the dtls1_get_message_fragment()
    function related to anonymous ECDH cipher suites. This
    could allow denial of service attacks. Note that this
    issue only affects OpenSSL TLS clients. (CVE-2014-3470)

Note that these issues only affects devices with J-Web or the SSL
service for JUNOScript enabled.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10629");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10629.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");
include("global_settings.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

# Versions 14 and later are not affected
ver_array = split(ver, sep:".", keep:FALSE);
ver_first = int(ver_array[0]);

if (ver_first > 14) audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

fixes    = make_array();
fix      = NULL;
fixed    = NULL;
nofix    = NULL;

if (ver =~ "^11\.4[^0-9]")
{
  fixes['11.4'] = '11.4R12-S4';
  fix = check_junos(ver:ver, fixes:fixes);
  if (fix)
  {
    fixed = '\n    CVE-2014-0198 (fixed in 11.4R12-S4)';

    fixes['11.4'] = '11.4R12-S1';
    fix = check_junos(ver:ver, fixes:fixes);
    if (fix)
    {
      fix = "11.4R12-S4 \ 11.4R12-S1";
      fixed += '\n    CVE-2014-0076, CVE-2014-0224 (fixed in 11.4R12-S1)';
    }
    else
      fix = "11.4R12-S4";
  }
  nofix = "CVE-2010-5298";
}

else if (ver =~ "^12\.1X44[^0-9]")
{
  fixes['12.1X44'] = '12.1X44-D40';
  fix = check_junos(ver:ver, fixes:fixes);
  if (fix)
    fixed = "CVE-2010-5298, CVE-2014-0076, CVE-2014-0198, CVE-2014-0224";
}

else if (ver =~ "^12\.1X46[^0-9]")
{
  fixes['12.1X46'] = '12.1X46-D20';
  fix = check_junos(ver:ver, fixes:fixes);
  if (fix)
    fixed = "CVE-2010-5298, CVE-2014-0076, CVE-2014-0198, CVE-2014-0224";
}

else if (ver =~ "^12\.1X47[^0-9]")
{
  fixes['12.1X47'] = '12.1X47-D15';
  fix = check_junos(ver:ver, fixes:fixes);
  if (fix)
  {
    fixed = '\n    CVE-2014-0198, CVE-2014-0224 (fixed in 12.1X47-D15)';
    fixes['12.1X47'] = '12.1X47-D10';
    fix = check_junos(ver:ver, fixes:fixes);
    if (fix)
    {
      fix = '12.1X47-D15 / 12.1X47-D10';
      fixed += '\n    CVE-2010-5298, CVE-2014-0076 (fixed in 12.1X47-D10)';
    }
    else
      fix = "12.1X47-D15";
  }
}

else if (ver =~ "^12\.2[^0-9]")
{
  fixes['12.2'] = '12.2R9';
  fix = check_junos(ver:ver, fixes:fixes);
  if (fix)
    fixed = "CVE-2010-5298, CVE-2014-0076, CVE-2014-0198, CVE-2014-0224";
}

else if (ver =~ "^12\.3[^0-9]")
{
  fixes['12.3'] = '12.3R8';
  fix = check_junos(ver:ver, fixes:fixes);
  if (fix)
  {
    fixed = '\n    CVE-2014-0198, CVE-2014-0224 (fixed in 12.3R8)';

    fixes['12.3'] = '12.3R7';
    fix = check_junos(ver:ver, fixes:fixes);
    if (fix)
    {
      fix = "12.3R8 \ 12.3R7";
      fixed += '\n    CVE-2010-5298, CVE-2014-0076 (fixed in 12.3R7)';
    }
    else
      fix = "12.3R8";
  }
}

else if (ver =~ "^13\.1[^0-9]")
{
  fixes['13.1'] = '13.1R4-S3';
  fix = check_junos(ver:ver, fixes:fixes);
  if (fix)
  {
    fixed = '\n    CVE-2010-5298, CVE-2014-0076, CVE-2014-0198 (fixed in 13.1R4-S3)';
    fixes['13.1'] = '13.1R4-S2';
    fix = check_junos(ver:ver, fixes:fixes);
    if (fix)
    {
      fix = "13.1R4-S3 \ 13.1R4-S2";
      fixed += '\n    CVE-2014-0224 (fixed in 13.1R4-S2)';
    }
    else
      fix = "13.1R4-S3";
  }
}

else if (ver =~ "^13\.2[^0-9]")
{
  fixes['13.2'] = '13.2R5-S1';
  fix = check_junos(ver:ver, fixes:fixes);
  if (fix)
  {
    fixed += '\n    CVE-2014-0076, CVE-2014-0198 (fixed in 13.2R5-S1)';
    fixes['13.2'] = '13.2R5';
    fix = check_junos(ver:ver, fixes:fixes);
    if (fix)
    {
      fix = "13.2R5-S1 \ 13.2R5";
      fixed += '\n    CVE-2010-5298, CVE-2014-0224 (fixed in 13.2R5)';
    }
    else
      fix = "13.2R5-S1";
  }
}

else if (ver =~ "^13\.3[^0-9]")
{
  fixes['13.3'] = '13.3R3';
  fix = check_junos(ver:ver, fixes:fixes);
  if (fix)
  {
    # nb 13.3 is not affected by CVE-2014-0076
    fixed = '\n    CVE-2010-5298, CVE-2014-0198, CVE-2014-0224 (fixed in 13.3R3)';
    fixes['13.3'] = '13.3R2-S3';
    fix = check_junos(ver:ver, fixes:fixes);
    if (fix)
    {
      fix = "13.3R3 \ 13.3R2-S3";
      fixed += '\n    CVE-2010-5298, CVE-2014-0224 (fixed in 13.3R2-S3)';
    }
    else
      fix   = '13.3R3';
  }
}

else if (ver =~ "^14\.1[^0-9]")
{
  fixes['14.1'] = '14.1R2';
  fix = check_junos(ver:ver, fixes:fixes);
  if (fix)
    fixed = "CVE-2014-0198";
}

# Check if host is affected
if (isnull(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

# HTTPS or XNM-SSL must be enabled
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  patterns = make_list(
    "^set system services web-management https interface", # HTTPS
    "^set system services xnm-ssl" # SSL Service for JUNOScript (XNM-SSL)
  );
  foreach pattern (patterns)
  {
    if (junos_check_config(buf:buf, pattern:pattern))
    {
      override = FALSE;
      break;
    }
  }
  if (override) audit(AUDIT_HOST_NOT,
    'affected because J-Web and SSL Service for JUNOScript (XNM-SSL) are not enabled');
}

# Report
if (report_verbosity > 0)
{
  report =
    '\n  Installed version    : ' + ver +
    '\n  Fixed version        : ' + fix;

  if (!isnull(fixed))
    report += '\n  CVEs fixed           : ' + fixed;

  if (!isnull(nofix))
    report += '\n  No fix available for : ' + nofix;

  report += '\n';

  security_warning(port:0, extra:report + junos_caveat(override));
}
else security_warning(port:0, extra:junos_caveat(override));
