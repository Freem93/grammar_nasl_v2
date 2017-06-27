#TRUSTED 603dda2db3a4f1c0f0e8a7d43936551821ee77d54e343da5492cb35ee41b3bc98c323fbebe7c6f189fd191bcce6e12cc6a53ab1ad4cbff494420823fab779e184358bf4383604c83d1fde65d67c05ad42665a1b33f5fb01f11b00ce09b707f5f1e98a6bf7c9bca069fb2c90aceb0e6f4040b16d9e9553ca3a99429ef45a7ec3f28cd3339b02f9b391a2bd23fdfad230f189b451d01289ef3a7bed0099267e3fa25cf1d91cd8f1e62be1f0ebf27380fa70507fd471d3a32dbc19cc6268c778d8fab34f1a8be7e7aea677c436d913607020097b52415b55a779dd987c94c8d6a4298538d09b043daf11afb86f5ed000011f3e3b626b332e20443cf78522915864e380012a34950aa1d83e7618a7f645b396eb5117af9d4f8f842abce40ed9c2dd47c8ac44838114aba73423b8c3d3c5ce3e8a26bdcadbcb49d4f345e759808e069e6d2590346669a784001c124e449aa40a157470be4b996f8536ad64e5973353cb50c88b9f2ddddf85381d560012666de6f30f5f7360a6e20f50dfdd5317b1799e5e33fb5447cf05e3a4bc3e97786e21152768f044fc9992dd208ec6b472b343ff4c95b65e87cd2b12f8087d8e9f21540ae68e12cc35109b14140fd0f98485a22f600e288eb23338ba22415d6ec244e1c2b3148935d36bb09eff9750afd7d70e940886881864553c92606d3963ff788f9c3a1d40ec836f877782eaacbaef11c81
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76588);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/11/14");

  script_cve_id("CVE-2013-5567");
  script_bugtraq_id(68504);
  script_osvdb_id(108983);
  script_xref(name:"CISCO-BUG-ID", value:"CSCui45606");

  script_name(english:"Cisco ASA Inspection and Filter Overlap DoS (CSCui45606)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of the remote Cisco ASA device is
affected by a denial of service vulnerability due to improper handling
of traffic matching both filtering and inspection criteria that could
allow a remote attacker to cause the device to reset.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2013-5567
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a4835b13");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCui45606");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Bug ID CSCui45606 or
apply the vendor-supplied workaround.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/18");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

asa   = get_kb_item_or_exit('Host/Cisco/ASA');
model = get_kb_item_or_exit('Host/Cisco/ASA/model');

ver = extract_asa_version(asa);
if (isnull(ver)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

if (model !~ '^55[0-9][0-9](|-)X($|[^0-9])') audit(AUDIT_HOST_NOT, 'ASA 5500-X series');

fixed_ver = NULL;

if (ver == "8.4(6)")
  fixed_ver = "8.4(7.1)";
else
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", ver);

override = FALSE;

# Check if the misconfiguration is present;
# can be removed via workaround
if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  buf = cisco_command_kb_item(
    "Host/Cisco/Config/show_running-config_service", # currently, should not be present
    "show run | include service"
  );
  if (check_cisco_result(buf))
  {
    if (
      "service resetoutside" >< buf &&
      "service resetinbound" >< buf &&
      "no service resetoutbound" >!< buf
    ) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected");
}

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fixed_ver +
    '\n';
  security_warning(port:0, extra:report+cisco_caveat(override));
}
else security_warning(port:0, extra:cisco_caveat(override));
