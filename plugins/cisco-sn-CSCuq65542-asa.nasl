#TRUSTED 2cc6636a7b02dee389c1e7a88fe5fa328bc38854b75ea8b735ba260e7050173eb40623497950e1cee5b8b80b3cd22519e84aa35c5bc29549baf9bca98f4cec82cf9891c89605ee63c446649d07404615ed0f0099c39d14d06e543563a9c276eff23a05392c09cb2139c581594d098b2b1b023ed8b08da75f096608c483e52205a70048613b1c8de2e92d31a0d8a444b0e08c2a7799537551660e229f88a311b6eda72698e438d6687a89e7d91b4fcfe2ba000d9d6c241f831becdcf3dcd6ee20d3b9ffc356d2f889ef6b5ad68d314d5cdc2a7b15dfde1a7d83fac203f211f9bef5f2944064c53a5535c7e76e5ea21151cd94e85ff9bbdc075d7de2bf9daa920e23f1d7beb7cfa900d523f9c5fbb96ad1389b4bcead18a4363033d1f8bf3213be627f7a3e821f97974bb4c61819bccb0104deffeddbcc9effcf5cc38055d204139d0f0021a45a0be541823c39958843adbdb4eadfad9d9285c79c480e1e03d57db4f712c2bd9e714f4c8b04a4f99f954abebd0c4604959ff806898f69de8c800e249bffcf703bd02ccf3681aa82091f56f13a02be071113d4e0191fca50dd0c12556a956b48a35b01374d0781564da8eff5cc1b56bc9e851764ad7c206e965bfdc23e9d569e0e9f3834b4744de5132d206c25822dcad73caae1c50343d5469b0a1d9def3536a5d6ea26f6d9a86d44de32c72514e5acb42a0cab0dc89e741a790d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79359);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-3398");
  script_bugtraq_id(70230);
  script_osvdb_id(112670);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuq65542");

  script_name(english:"Cisco ASA SSL VPN Information Disclosure (CSCuq65542)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of the Cisco ASA software on the
remote device is affected by an information disclosure vulnerability
in the SSL VPN feature. By requesting a specific URL, a remote
attacker can exploit this vulnerability to obtain software version
information which could be used for reconnaissance attacks.

Note that the SSL VPN feature must be enabled for the device to be
affected by this vulnerability.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2014-3398
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ea385c92");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=35946");
  script_set_attribute(attribute:"solution", value:"Apply the relevant patch referenced in Cisco bug ID CSCuq65542.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/20");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

asa   = get_kb_item_or_exit('Host/Cisco/ASA');

ver = extract_asa_version(asa);
if (isnull(ver)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

fixed_ver = NULL;

if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(7.23)"))
  fixed_ver = "8.4(7.23)";

else if (ver =~ "^8\.6[^0-9]")
  fixed_ver = "Refer to the vendor.";

else if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(4.25)"))
  fixed_ver = "9.0(4.25)";

else if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(5.15)"))
  fixed_ver = "9.1(5.15)";

else if (ver =~ "^9\.2[^0-9]" && check_asa_release(version:ver, patched:"9.2(2.7)"))
  fixed_ver = "9.2(2.7)";

if (isnull(fixed_ver))
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", ver);

flag     = FALSE;
override = FALSE;

# Check if SSL VPN (WebVPN) feature is enabled
if (get_kb_item("Host/local_checks_enabled"))
{
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_webvpn", "show running-config webvpn");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"enable", string:buf)) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;
}

if (!flag && !override) audit(AUDIT_HOST_NOT, "affected");

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fixed_ver +
    '\n';
  security_warning(port:0, extra:report+cisco_caveat(override));
}
else security_warning(port:0, extra:cisco_caveat(override));
