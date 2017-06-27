#TRUSTED a155a4ac5dad1a081be885356b439af7e990ceab93184b20e6e0705d838398e61ec8f373044bf690755414d6d21a07e6da8a1ab077e7ab9c95bafc8cac1f8f35810505b3a03be9bc17da509955cafa791b3d65241844c86eee240497feaed758501293998e0bd5bc7ea4ff2f0518c5ba7ee6a9ddfdba11ec7d0bd0cca3969c4ac573ba4aa8e11802fea739d6aaa2413edb439ea33b2d37b36afe17b4d104497c43f69b070cd8634b825338df5b225673a4d87e3e1e9a9bde1c21013c5c045e625ea84f015ea92c4e896f9fb4ba3bf05b06243d8baa038f00406dead3d8b98481a58d77415732849de57e9b3be367d4b21baf3338d92ea16df98f41725d85b89c7fbb860169548bfbbf9a2fbd0e71ce9b381c3d5cc3ec0ae4a39c8612a1579adeb4d1f3b73602c47e4fc4609722587eb5f25376243ac7213ce99c40523bbd90d0b8a56999a4faed50fd47c21f11d1567c38df9a4394a31e43b8a8e76a1e92d447ff5497e3056d77ba26d2b1fa50295426b9045357bc30e5143ebd07c77e2fc1df3ae93b6ab2740b5f4b13c2faf9721ebf01a2c4beb96bb0abd5def05b4067433cff97a519a4db0073dacae7f9747eee4e6b41c39c71c5dceb1600c4328a7813e9b4bfa9a4e8cd063e1090fa974566d77658b00686b0ec249425ef7ef61bd98f6ab5e778c4dad35bb13eb2110cde37cd4671db805a88696e54e80ff346040c7726
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78030);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-3357", "CVE-2014-3358");
  script_bugtraq_id(70132, 70139);
  script_osvdb_id(112040, 112041);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuj58950");
  script_xref(name:"CISCO-BUG-ID", value:"CSCul90866");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140924-mdns");

  script_name(english:"Cisco IOS XE Software Multiple mDNS Gateway DoS Vulnerabilities (cisco-sa-20140924-mdns)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS XE
running on the remote host is affected by two unspecified denial of
service vulnerabilities in the multicast DNS (mDNS) implementation. A
remote attacker can exploit this issue by sending a specially crafted
mDNS packet to cause the device to reload.

Note that mDNS is enabled by default if the fix for bug CSCum51028 has
not been applied.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140924-mdns
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f9e02dba");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAMBAlert.x?alertId=35023");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=35607");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=35608");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCuj58950");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCul90866");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20140924-mdns.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/02");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

app = "Cisco IOS XE";
cbi = "CSCuj58950 and CSCul90866";
fixed_ver = NULL;


if (
  ver =~ "^2\.[16]\.[0-2]$" ||
  ver =~ "^2\.2\.[1-3]$" ||
  ver =~ "^2\.3\.([02]|[01]t)$" ||
  ver =~ "^2\.4\.[01]$" ||
  ver == "2.5.0" ||
  ver =~ "^3\.1\.[0-3]S$" ||
  ver =~ "^3\.[2356]\.[0-2]S$" ||
  ver =~ "^3\.4\.[0-6]S$" ||
  ver =~ "^3\.7\.[0-4]S$"
)
  fixed_ver = "3.7.6S";

else if (
  ver =~ "^3\.2\.[0-3]SE$" ||
  ver =~ "^3\.3\.[01]SE$"
)
  fixed_ver = "3.3.2SE";

else if (ver =~ "^3\.3\.[0-2]SG$")
{
  cbi = "CSCuj58950";
  fixed_ver = "3.4.4SG";
}
else if (ver =~ "^3\.4\.[0-3]SG$")
  fixed_ver = "3.4.4SG";

else if (ver == "3.3.0XO")
  fixed_ver = "3.3.1XO";

else if (ver == "3.5.0E")
  fixed_ver = "3.5.2E";

else if (
  ver =~ "^3\.8\.[0-2]S$" ||
  ver =~ "^3\.9\.[01]S$" ||
  ver =~ "^3\.10\.(0|0a)S$"
)
  fixed_ver = "3.10.4S";

else if (ver =~ "^3\.11\.[12]S$")
  fixed_ver = "3.12.0S";

if (isnull(fixed_ver)) audit(AUDIT_INST_VER_NOT_VULN, app, ver);


# mDNS check
override = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_udp", "show udp");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"^17\S+\s+\S+\s+5353\s+", string:buf)) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because mDNS is not enabled.");
}

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
