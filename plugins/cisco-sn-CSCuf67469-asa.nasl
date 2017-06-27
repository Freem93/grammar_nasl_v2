#TRUSTED 62e78f80f8af6889dcaa308221977734ce65c5199538059a6711ff42fa594ba451c5f52382557081043656462ce99b5ff5ae568d8ec2b2ce3d7434ce46ba31e0bc60309559b8caf8ab10beba9b676afe342fab82c33280f1913f4efba70861a562f93bb4f9cb8c058bf9532e57991085f392fea3df464cba181a09797f03587d85d2704ff22e23d1f9a5112e11dd714b19debe3b90c859b873d314ab5044750557bb2d28f8a51e5ca0571894b6ae06632fd21e822d29cc367f3d94b493eaf13df43a4b389a3063642877129e7414f20615cad69012eae9250e734a30ae1e513e4d3ef9658ec30a7228d164291c0c6eae41e8f487a978c041d752028d5704d16264c31c5359eddb59a40d4a94ef4583984f6a5f9d36c29b71c3c5ca1f1c16682c18ddb56be7126845418792e1a418440e15c161b30e39b08f5f5951cd253059001dc18a300b776e109d77491210b5d23308467dda425f04a58973100f8c65230a5821223fcf7ba85d6637e1d6be1f69417e719f277b66495db9ff8206bad397cd2155f914e1717e331e136aca8a855342cc18bd57479625513bfea8078fcb507675168e3612a9ffa35f43ac82c7d4bb5891adf907066d37c5c280daebcbc465bd34c5e4d58b9c72248d81961a755bc07107f5d0a3c15504253444ebedb84b6c03224586b42bdf2ecd853042946ac6a22c800ddd1d00e155cc747bf2af61921447
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73827);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/05/02");

  script_cve_id("CVE-2014-2154");
  script_bugtraq_id(67036);
  script_osvdb_id(106130);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuf67469");

  script_name(english:"Cisco ASA SIP Inspection DoS (CSCuf67469)");
  script_summary(english:"Checks ASA version");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco Adaptive Security Appliance (ASA) Software contains a
vulnerability that could allow an unauthenticated, remote attacker to
cause a memory leak which can be exploited to create a denial of
service condition.

The vulnerability is due to improper handling of Session Initiation
Protocol (SIP) packets. An attacker could exploit this vulnerability
via specially crafted SIP packets.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2014-2154
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?729c7b90");

  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Bug Id CSCuf67469.

Alternatively, the vendor has provided a workaround that involves
disabling SIP inspection on the affected device.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");

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

asa = get_kb_item_or_exit('Host/Cisco/ASA');
model = get_kb_item_or_exit('Host/Cisco/ASA/model');
version = extract_asa_version(asa);
if (isnull(version)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

# Cisco ASA 5500-X Next Generation Firewall
if (model !~ '^55[0-9][0-9]-?X') audit(AUDIT_HOST_NOT, 'ASA 5500-X');

temp_flag = 0;
if (get_kb_item("Host/local_checks_enabled")) local_check = 1;

if (
  cisco_gen_ver_compare(a:version, b:"8.4(5)") == 0 ||
  cisco_gen_ver_compare(a:version, b:"8.4(5.6)") == 0
)
  temp_flag++;

if (local_check)
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item(
      "Host/Cisco/Config/show_service-policy-include-sip",
      "show service-policy | include sip"
    );
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, icase:TRUE, pattern:"Inspect: sip", string:buf))
        temp_flag = 1;
    }
    else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1; }
  }
}

if (temp_flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 8.4(6.1) / 8.4(6.99) / 8.4(7)' +
      '\n';
    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  else security_warning(0);
}
else audit(AUDIT_HOST_NOT, "affected");
