#TRUSTED 44433fd8efa73495e223d6cc129ed016a1e99cc3abc124ffe352f4aab48098f0458fa96e5fabc2445344f66e59c061a8933caa07e92a87034557046e70dc2f52f23795418d48f2f6334ba8bcd3a0e1ad2260cdb1fb18d3e6afc8b71b313f5dd12c9521dee32d77c6295630c4b9e1cda3ef653eef6d6cf7166fd1698732b56223e151ab933b337179cf18d906c75af1dfe380c61f35b4ef2858985a294af3b3a341ffc8f4aa2d26bf094685488b4e3559699a1242db558adb77178b2197aefff49db4e270918e6057c06109f262b8ca27c870f901d825f9d48325906be06a1fc01b33d5a3d8c46f8305e372f761ec57a2f712259cf0df31920278b751e0249b51202c7f0613dd75fbfb43f3d1313cbae08b77ffe0bdba70cc7beedd49a5b4b28bea6402543ec2de46b5a3b45ed80f4c9e076de6763a9dd4687635fbb506cb10ccc6e8ef3f8a879bf9f96b685083b6e7a6b1c6cbab04ef2ab1f508013ae610ec3cbb287628f236a379c95ac036ba0875e26826df6375fb665e590e4d7399a35407faa76a6a9170b945307fe48906eee4c829a71676ffcbde3669409410446c5e4032dba0e5c5f8f4ff5247de5975a3e47d2c57cb676aa2b45b0d7c8ce85884790d5f6a0d4992885cab56e99ec0a55a7a3110ad718d5a2dec927ee86a60e5720b9a1139637a0cecc3ca9e226293f1d0d2e630979bd8a9f8df54e30bd92122ad7f45
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82569);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/09/08");

  script_cve_id("CVE-2015-0646");
  script_bugtraq_id(73340);
  script_osvdb_id(119950);
  script_xref(name:"CISCO-BUG-ID", value:"CSCum94811");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150325-tcpleak");

  script_name(english:"Cisco IOS XE Software TCP Memory Leak DoS (cisco-sa-20150325-tcpleak)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is affected by a memory leak issue in the
TCP input module when establishing a three-way handshake. An
unauthenticated, remote attacker can exploit this issue, via specially
crafted TCP packets, to consume memory resources, resulting in a
device reload and a denial of service condition.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150325-tcpleak
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f66c26bd");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCum94811");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20150325-tcpleak.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

app = "Cisco IOS XE";
cbi = "CSCum94811";
fixed_ver = NULL;

if (
  ver =~ "^3.3.[0-2]XO$" ||
  ver =~ "^3.5.[0-3]E$"  ||
  ver =~ "^3.6.[01]E$"
)
  fixed_ver = "3.7.0E";

else if (
  ver =~ "^3.8.[0-2]S$"  ||
  ver =~ "^3.9.[0-2]S$"  ||
  ver =~ "^3.10.[0-4]S$" ||
  ver == "3.10.0S"       ||
  ver == "3.10.0aS"
)
  fixed_ver = "3.10.5S";

else if (
  ver =~ "^3.11.[0-4]S$" ||
  ver =~ "^3.12.[0-2]S$"
)
  fixed_ver = "3.12.3S";


if (isnull(fixed_ver)) audit(AUDIT_INST_VER_NOT_VULN, app, ver);

override = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;
  # TCP listening check
  # Example:
  # 03577CD8  ::.22                    *.*                    LISTEN
  # 03577318  *.22                     *.*                    LISTEN
  # 035455F8  ::.80                    *.*                    LISTEN
  # 03544C38  *.80                     *.*                    LISTEN
  buf = cisco_command_kb_item("Host/Cisco/Config/show_tcp_brief_all", "show tcp brief all");
  if (check_cisco_result(buf))
  {
    if ( preg(multiline:TRUE, pattern:"^\S+\s+\S+(\.\d+)\s+\S+\s+(LISTEN|ESTAB)", string:buf))
      flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  # TCP control-plane open-ports
  # tcp                        *:22                         *:0               SSH-Server   LISTEN
  # tcp                        *:22                         *:0               SSH-Server   LISTEN
  # tcp                        *:80                         *:0                HTTP CORE   LISTEN
  # tcp                        *:80                         *:0                HTTP CORE   LISTEN
  buf = cisco_command_kb_item("Host/Cisco/Config/show_control-plane_host_open-ports", "show control-plane host open-ports");
  if (check_cisco_result(buf))
  {
    if ( preg(multiline:TRUE, pattern:"^(\s)?+tcp\s+\S+\s+\S+\s+.*(LISTEN|ESTABLIS)", string:buf))
      flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;
}

if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because nothing is listening on TCP");

if (report_verbosity > 0)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver +
    '\n';
  security_hole(port:0, extra:report+cisco_caveat(override));
}
else security_hole(port:0, extra:cisco_caveat(override));
