#TRUSTED 2e51c21ef1835564ff0be34b501e4f928e9ba90ed9fb7c31c614ac94f9514bc66bc1ff209914d17c5edae86f88c0f7eaaa4b1701e6ce1783fd696ea9e93eab5874c292f172aafb026726338aadaef20b839fb658d8d50237f89c34b2588b2e4f2c9972c45e04de40aa654e1e1f195a12d76dcb169ed55ca90159341b94d1e387c9177f106d23ceb0c9060d6d91cc14961db4e5d186f9fe0ebd2eab28816f17b2b6c26842e37b7a006809241146dc1cfed7ff6e38695c1bdca101ca23e9be1ac900eb968d7286756a270ee03563c46a6f3aa04cea5b08214451dd345081edd6ebce99ba8f124d629dc5b3ad56b6de5aec7503b53ac2d3733cf53d6782b2208249a8d7f3c6167c44ca4570e77b88ee59c781411ebf7bc591de44691eada9ad8dd1d84f6b94d931839df07d8aaaa2179ccf9cb1b21779da3a90be19e8f0b1180e21ea0994ca33d55994e2da1f0ba82f6290668213c1cd4b6f9d8f1ed4a624fa160023038223e0598393de487350480a7f2f14e9a358655310e14cb0b682d9cab7ba912d130d45ef21fdb78303a222e8bdec1235217e1873a1589c70d95a33e9e9125010b50087e2839c88e98e6da6bea115f4ca811795ee36990c3f14efb7a76033e405f22582a8c6ea241158e00acb7801751fd2a02dd2d69def123491fa536eca807ce7ab7e58863685e07dc2c3a249c7d4daf4786e98b38b946ba1b839550c9c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78557);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2013-5566");
  script_bugtraq_id(63564);
  script_osvdb_id(99521);
  script_xref(name:"CISCO-BUG-ID", value:"CSCte27874");

  script_name(english:"Cisco MDS 9000 VRRP DoS (CSCte27874)");
  script_summary(english:"Checks the NX-OS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote host is an MDS 9000 series router. It is, therefore,
vulnerable to a denial of service vulnerability. A flaw with Virtual
Router Redundancy Protocol (VRRP) frame handling allows a remote
attacker, using a specially crafted VRRP frame with an Authentication
Header (AH), to cause the device to have high CPU utilization and
force a restart of the device.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2013-5566
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d4ddd48b");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=31663");
  script_set_attribute(attribute:"solution", value:"Apply the patch referenced in Cisco bug ID CSCte27874.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Device", "Host/Cisco/NX-OS/Model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

device = get_kb_item_or_exit("Host/Cisco/NX-OS/Device");
model = get_kb_item_or_exit("Host/Cisco/NX-OS/Model");
version = get_kb_item_or_exit("Host/Cisco/NX-OS/Version");

# only affects MDS 9000 series systems
if (device != 'MDS' || model !~ '^9[0-9][0-9][0-9]([^0-9]|$)') audit(AUDIT_HOST_NOT, "affected");

flag = 0;
override = 0;

if (version == "2.1") flag ++;
if (version == "3.0") flag ++;
if (version == "3.2") flag ++;
if (version == "4.1") flag ++;
if (version == "4.1(1b)") flag ++;
if (version == "4.1(1c)") flag ++;
if (version == "4.1(3a)") flag ++;
if (version == "4.2") flag ++;
if (version == "4.2(1a)") flag ++;
if (version == "4.2(1b)") flag ++;
if (version == "4.2(3)") flag ++;
if (version == "5.0") flag ++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_aclmgr",
                                "show running-config aclmgr");
    if (check_cisco_result(buf))
    {
      if (!preg(multiline:TRUE, pattern:"interface mgmt0", string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCte27874' +
      '\n  Model             : ' + device + ' ' + model +
      '\n  Installed version : ' + version +
      '\n';
    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  else security_warning(port:0, extra: cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
