#TRUSTED 8db1f9e25eb754d8723389b264017dca4143149bb12632680b03f9fcfc27ffdcfea201891738de8d6126f8c836a856926c4ef582ec37da7570b99a8e387972b252ac958498df15429512b92756a3d0b75e4634abf7587ceb356f25b730f80b8769cc62b54bfafc2b150b691672e983f9bd70cf491b74f4c75a95115ef3533db3f9948bb97bc2adb2a93283eed8e3ce2d68b21b858a54ce2a8f2a23d35b47a1bc81f94b881535eedd38eec6c9ec9a5936a146433c349feece17bdf86820c0b2a2d9591a66d1c3af58ca5ec902146092788d3e3e76002e99ce0f7c35c846300c1d2d4dcb5f15152ac7d77da5aa128b729587103789b743ca45aaef48fae7475d144083cf1af068c4f4bba369a94b2bd78ae4b31a73178f071d3ffa75ac5c9e727915d63cfee291cb128f9edd5229c6a88524b05d571335e5cf6941109cadc32812e35a114247a48181626ad738c00c1a9bcac6b2ef27f47f074745907a6feab178543cb4faef02ad0032fb6b77dc005bea9903d075cc23a1d367d100665afeff18b15dffda401969f88939ea17f421bea229d91f02c85e3855ee168cdcbe749432823a13f29bc22bf21cfd183737c45e4ec804642dca5a003f47afe2c8878999caa985e6c14a8200c6d13867aee51bb9d74fddbd12530657166e4362e763675ebcbd52d7fb8d8dc23fbfe4fc090ff15674d81066afce3258deb012a3fb1857654c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70476);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2013-6015");
  script_bugtraq_id(62963);
  script_osvdb_id(98368);
  script_xref(name:"JSA", value:"JSA10596");

  script_name(english:"Juniper Junos SRX Series flowd Remote DoS (JSA10596)");
  script_summary(english:"Checks the Junos version, model, build date, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos SRX-series device has a denial of service vulnerability related
to processing particular TCP packet sequences. A remote attacker can
exploit this issue to cause the flow daemon (flowd) to crash.

Note that this issue only affects devices with ALG and UTM enabled.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10596");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10596.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version", "Host/Juniper/JUNOS/BuildDate");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
build_date = get_kb_item_or_exit('Host/Juniper/JUNOS/BuildDate');

check_model(model:model, flags:SRX_SERIES, exit_on_fail:TRUE);

if (compare_build_dates(build_date, '2013-09-18') >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver + ' (build date ' + build_date + ')');
if (ver == '11.4R5-S2')
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

fixes = make_array();
fixes['10.4'] = '10.4S14';
fixes['11.4'] = '11.4R6';
fixes['12.1'] = '12.1R3';
fixes['12.1X44'] = '12.1X44-D20';
fixes['12.1X45'] = '12.1X45-D15';
fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# UTM or ALG must be enabled
override = TRUE;
if (get_kb_item("Host/local_checks_enabled"))
{
  buf = junos_command_kb_item(cmd:"show security utm web-filtering status");
  if (buf)
  {
    override = FALSE;
    pattern = "^\s+Server status:.*up$";
    if (preg(string:buf, pattern:pattern, icase:TRUE, multiline:TRUE))
      override = FALSE;
  }

  if (override)
  {
    buf = junos_command_kb_item(cmd:"show security alg status");
    if (buf)
    {
      pattern = ":\s*Enabled$";
      if (!preg(string:buf, pattern:pattern, multiline:TRUE))
        audit(AUDIT_HOST_NOT, 'affected because neither ALG nor UTM are enabled');
      override = FALSE;
    }
  }
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_HOLE);
