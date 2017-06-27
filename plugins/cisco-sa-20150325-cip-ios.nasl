#TRUSTED 4d3c6df03d92723c226f2f9cc0cd2037e24d5a9b65f702007b3ef9c257ddd7f44f9e6cc70700865231c226749060a2167306a44fc1a821e2515068a43072f143cd29aa5ac50e6ea010bccb9d86b4fdb34b549fcffbe75a35eebb86f8040dfced03a87f3207e1b4979917a5a6de88000dd2756ec8505ccce8e49b2157cff19c68342d44003ffcbd13b4f6ee03da748cdbea385e22662e2e126c9d23cc9d1f38c18c4f25c2e64257f82ee327b1f6f02bbeee0bb9f2a80efd779aa932f48b465dadf078bff9d68c20879c70dbc1b70c916dc55c3734375420eca70cf87055abfd52f21b525c15fafb5c3a725cd32de1b3390415fde95c9850978e9088cf43d29216c04fd1732696d85de30b03017bb285ee0460754534a69f0428e91b824fd2394071728ab7b469a9e7b4e02a941a19e5b26377392d25dbb59ab585a9c66cb0cf1f9da80d3350f4f32ff3272e230888618f316610966605f830aa5c697f736d3e7a11e7f40cff3dce6067b18df479841af310f18e315f43b93b5b3fae58e25a7abc02b99fa8b24948d5a9b5989142f3a7037de58931ded683dfd33cf40c1609c95c922c97a85662d846f09e71db086645b7f7e1eb3fbc4ba73edf325a13db737a2ffb356cb8718d520bf12610404e02b2618121c5ad7af1d7d427fa5d716a38f3cbaabba7f4129fc2030e49bb9ae2bb84686d0f53e32c6eae51f4f4151fd8e8552c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82571);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2015-0649");
  script_bugtraq_id(73334);
  script_osvdb_id(119935);
  script_xref(name:"CISCO-BUG-ID", value:"CSCun63514");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150325-cip");

  script_name(english:"Cisco IOS Software TCP CIP DoS");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS software running
on the remote device is affected by a flaw in the Common Industrial
Protocol (CIP) implementation due to improper handling of crafted TCP
packets sent to a CIP port. A remote, unauthenticated attacker can
exploit this to cause a device reload, resulting in a denial of
service.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150325-cip
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8a443811");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=37819");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/03");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

vuln_versions = make_list(
  "12.2(33)IRD1",
  "12.2(33)IRE3",
  "12.2(33)SXI4b",
  "12.2(44)EX",
  "12.2(44)EX1",
  "12.2(44)SQ1",
  "12.2(46)SE",
  "12.2(46)SE1",
  "12.2(46)SE2",
  "12.2(50)SE",
  "12.2(50)SE1",
  "12.2(50)SE2",
  "12.2(50)SE3",
  "12.2(50)SE4",
  "12.2(50)SE5",
  "12.2(52)SE",
  "12.2(52)SE1",
  "12.2(55)SE",
  "12.2(55)SE3",
  "12.2(55)SE4",
  "12.2(55)SE5",
  "12.2(55)SE6",
  "12.2(55)SE7",
  "12.2(55)SE8",
  "12.2(55)SE9",
  "12.2(58)SE2",
  "12.2IRD",
  "12.2IRE",
  "12.2SE",
  "12.2SQ",
  "12.2SXI",
  "12.4(25e)JAM1",
  "12.4(25e)JAN",
  "12.4(25e)JAP1m",
  "12.4(25e)JAZ1",
  "12.4JAM",
  "12.4JAP",
  "12.4JAZ",
  "15.0(1)EY",
  "15.0(1)EY1",
  "15.0(1)EY2",
  "15.0(2)EA",
  "15.0(2)EB",
  "15.0(2)ED1",
  "15.0(2)EY",
  "15.0(2)EY1",
  "15.0(2)EY2",
  "15.0(2)EY3",
  "15.0(2)SE",
  "15.0(2)SE1",
  "15.0(2)SE2",
  "15.0(2)SE3",
  "15.0(2)SE4",
  "15.0(2)SE5",
  "15.0(2)SE6",
  "15.0(2)SE7",
  "15.0(2a)SE6",
  "15.0EB",
  "15.0ED",
  "15.0EY",
  "15.0SE",
  "15.2(1)EX",
  "15.2(1)EY",
  "15.2(1)EY1",
  "15.2(2)E",
  "15.2(2)E1",
  "15.2(2)JA",
  "15.2(2)JB1",
  "15.2(2b)E",
  "15.2(4)JAZ",
  "15.2E",
  "15.2EX",
  "15.2EY",
  "15.2JAZ",
  "15.2JB",
  "15.3(2)S2",
  "15.3(3)JA",
  "15.3(3)JA1",
  "15.3(3)JA100",
  "15.3(3)JA1m",
  "15.3(3)JA1n",
  "15.3(3)JA2",
  "15.3(3)JA75",
  "15.3(3)JAA",
  "15.3(3)JAB",
  "15.3(3)JAB1",
  "15.3(3)JN",
  "15.3(3)JNB",
  "15.3JA",
  "15.3JAB",
  "15.3JN",
  "15.3JNB",
  "15.3S"
);

foreach version (vuln_versions)
{
  if (ver == version)
  {
    flag++;
    break;
  }
}

# Check that cip is enabled
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config",
                              "show run | include cip");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"cip enable", string:buf)) 
      flag++;
  }
  else if (cisco_needs_enable(buf))
  {
    flag++;
    override++;
  }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCun63514' +
      '\n  Installed release : ' + ver +
      '\n';
    security_hole(port:0, extra:report + cisco_caveat(override));
    exit(0);
  }
  else security_hole(0);
}
else audit(AUDIT_HOST_NOT, "affected");
