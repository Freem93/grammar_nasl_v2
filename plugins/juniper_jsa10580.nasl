#TRUSTED 3ab7d6007b75c5a08f78d74120687076941f1c366764c8672bd911b4530dd12a8ff31fd5edfd23bc93df72d42daa9bbf1d39254b2d846a0563c61660a1002acad0c9951feeead20e7ff9654f890337a98898a963768b19eaf9361ef26b7be653ca2addc760bb335c901945f767e46b3313eec0b45f2b725948f1ecd4304922f5abb498e47bba4d978438b6d72db3265bf97cfc494f02f6c2ea8b2d8d36687895811f3a83749bfa1a3826e1a96adddbdac69b57bfeb92c110462e8372e7cf44a4d7865e64eef11167a05f85febeacb43d9c42343eb1c16b78f11f026d3b2db2b1669ffaed94b9d7e099423f8f875d79a7727da442eee9fe89df4b576c193701c18414b0182ff3155e7cbbe1cbcc1ed4bfc82a48d829a7c7a12f6b2ef32851d7d6b3d14291322c22c771eb1b053c12c9026d35d4c9cb9a3840ebf922ab9877e7f7acba94e6dfc02c7e4c843e531d4fedca027e6b078bbe029a02bb0ce8c6c0fcf26d33577398a0f80b6e7985d17722254f96da7dda188ed3ede185f05e281eac21d88001fae41f95779cc709bc3d60e7ad6c04303c8c8d8e50dd90b9a9d001c6ec67d2ff61e1e606f0365865ba40c888231814cbeeaf679f9f68a152e81daf291243342dcd711828d03ecb1d0b44b5a0069396734d6c881f2eed9a616f6304663a5e4ac3a5cc30424530851da6eabe9ec972834dc306b2a2d743b7a763f6b71c8c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(68913);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2011-1473");
  script_bugtraq_id(48626);
  script_osvdb_id(73894);
  script_xref(name:"JSA", value:"JSA10580");

  script_name(english:"Juniper Junos SSL/TLS Renegotiation DoS (JSA10580)");
  script_summary(english:"Checks the Junos version, build date, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a denial of service vulnerability. The
SSL/TLS implementation on the remote host allows clients to
renegotiate connections. The computational requirements for
renegotiating a connection are asymmetrical between the client and the
server, with the server performing several times more work. Since the
remote host does not appear to limit the number of renegotiations for
a single TLS / SSL connection, this permits a client to open several
simultaneous connections and repeatedly renegotiate them, possibly
leading to a denial of service condition.

Note that this issue only affects devices with J-Web or the SSL
service for JUNOScript enabled.");
  script_set_attribute(attribute:"see_also", value:"http://www.ietf.org/mail-archive/web/tls/current/msg07553.html");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10580");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10580.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/JUNOS/BuildDate");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
build_date = get_kb_item_or_exit('Host/Juniper/JUNOS/BuildDate');

if (compare_build_dates(build_date, '2013-06-13') >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver + ' (build date ' + build_date + ')');

fixes = make_array();
fixes['10.4'] = '10.4S14';
fixes['11.4'] = '11.4R7';
fixes['12.1'] = '12.1R6';
fixes['12.1X44'] = '12.1X44-D20';
fixes['12.2'] = '12.2R3';
fixes['12.3'] = '12.3R2';
fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

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
    if (junos_check_config(buf:buf, pattern:pattern)) override = FALSE;
  }
  if (override) audit(AUDIT_HOST_NOT,
    'affected because neither J-Web nor the SSL service for JUNOScript are enabled');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
