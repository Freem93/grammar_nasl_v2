#TRUSTED 86259559a19959e05832b20ea2e086dfc2b0ce0d2248d3bc6f89405e9d3526c951cde73a95156b24df5dc1397e1e8d399bc3c746fb45e1f552dd970085cee9df949754f50e4d0c8b205580a31383f920d3cb9bb8041be2d648b65b20e3f9edafe54441e36cc12f1502d57478d18b7b865648eceba927ef9b646e6c1ba7f55e26b58fc937b501fa5fd875a8b3d8b78a59c9973121695881796a492cebbda9d1bdd43696213c488bcadae43c793b0bcd4d900f4a9fa69e32467997cb2bcc612e5ffbba81d52ad5cc8e7df0047939fec2db9d6d22db7c200173d866b40ff57f06cb7bd1205e1c445334969bc5769583bd4f7dc530a6baae2efeb8104bd27dea8f4c5606144a6329359788de7677cd5fa13fe6cde107b42b9f83aa137e3e45335d2006a37e605827a8bfb595df76757b0a73d2cdb52b8f5154ccc0e1b65633314c4dca32d61b021346bd60adc4222c34965ddf108d3f155132180ab86a795e1b596dd907cb0151a3beab1d0c229510bdab8e92af84a20b78a8e4b09e555880169ed715e6a2372d7487c96e1fe7a0cb10e2e63c1ef1f7879c9f66f0d4dcf2a9a3c8b7e1f6b705e655aca4498a2237caae9206ba85fa8493971238ae865546c74510789d473d1db503308c4b09b154edd352d8b89be322118b4fd2c7be86c7ff34ac4dd7ae68ed09a8c55c7634eaa11bbb3153c5f15b1c2b2693c03d727c79b276b24b
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74443);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/11/01");

  script_cve_id("CVE-2014-3264");
  script_bugtraq_id(67547);
  script_osvdb_id(107084);
  script_xref(name:"CISCO-BUG-ID", value:"CSCun69561");

  script_name(english:"Cisco ASA RADIUS radius_rcv_auth DoS (CSCun69561)");
  script_summary(english:"Checks ASA version");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of the remote Cisco ASA device is
affected by a denial of service vulnerability due to improper
validation of RADIUS packets. A remote attacker that knows the RADIUS
shared secret could cause a denial of service by injecting a specially
crafted packet during a RADIUS authentication exchange.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2014-3264
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?11b62cc5");
  # http://tools.cisco.com/security/center/viewAlert.x?alertId=34273
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1772766c");
  script_set_attribute(attribute:"solution", value:"Apply the relevant patch referenced in Cisco Bug Id CSCun69561.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/11");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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

if (ver =~ "^8\.[46][^0-9]")
  fixed_ver = "Refer to the vendor for a fix.";

else if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(4.8)"))
  fixed_ver = "9.0(4)8";

else if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(5.1)"))
  fixed_ver = "9.1(5)1";

else if (ver =~ "^9\.2[^0-9]" && check_asa_release(version:ver, patched:"9.2(1.1)"))
  fixed_ver = "9.2(1)1";

else
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", ver);

override = FALSE;

# Check if RADIUS authentication is enabled
if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"aaa-server \S+ protocol radius", string:buf)) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because RADIUS is not enabled.");
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
