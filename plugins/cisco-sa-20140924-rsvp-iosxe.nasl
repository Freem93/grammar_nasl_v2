#TRUSTED 07c6723e33b67ac0f0a70786bc14b254c3328bdec115691a5d9f9d0db689132f0d8e050f55b71a080aad2681c1315f826e1fddc142d269e7fc51733b4e924696140d447181e3f74c252e5e94b4daeb38bcdd43882b10f24812c69bb711719b5124cb8c5a6bc451e4d58ad847441de73e7d5fbd9afce5ddf21637d8defe19a9047338d62cf75df1fcabbb723a269989306402acf4211e5af4766ef6cb97d1567100e754eebf8effcf9754a1d8c3fa5af92cc1e28a0e21c3af177a20a41e6d452347d27296e0c64741fdf1f4b6236461ff5887f29befe2dda4ff46ff3e798061701b2362959adde62c4593c91a6c6db7b8c1c5c986d265ab54bc69befb66cdcca64a68ea318c153e85a49cb73a64d1e5fe80634bed1de5a4cc8f2397da6ce97105432e8a817e595ee9adcd1de2efc1b40680ae379a3583ba12d67b1b7fabd30177c4343bf7143c291ffc63fd78c36e80a5abab449c7f64608bb8a110f5560bd0f423c99a664d757de77ed69156aa4bd4ee5f848276414e15543ca875ee66940547bd57565e0b0832ad2d1d1d8b69cd8cfffd6b486e0eec654eb807c019e7ad7aa4c81e86ef00e845bef3f784c338bfe7f748ea289af28a696ed60cd11a45901c0ce6222a0d9286578f87d057bc44d7dc895655fc49574e1a4764edd5c544c93811d3e10269cce662960e46bee013bf3a6f10e875d9f9de29fb8ec29a4acc134e3a
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78034);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-3354");
  script_bugtraq_id(70131);
  script_osvdb_id(112037);
  script_xref(name:"CISCO-BUG-ID", value:"CSCui11547");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140924-rsvp");

  script_name(english:"Cisco IOS XE Software RSVP DoS (cisco-sa-20140924-rsvp)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS XE
running on the remote host is affected by a denial of service
vulnerability in the Resource Reservation Protocol (RSVP)
implementation due to improper handling of RSVP packets. A remote
attacker can exploit this issue by sending specially crafted RSVP
packets to cause the device to reload.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140924-rsvp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?76088c2b");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=35621");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCui11547");

  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20140924-rsvp.");
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
cbi = "CSCui11547";
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
  ver =~ "^3\.7\.[0-3]S$"
)
  fixed_ver = "3.7.6S";

else if (
  ver =~ "^3\.2\.[01]SE$" ||
  ver =~ "^3\.3\.[01]SE$"
)
  fixed_ver = "3.3.2SE";

else if (
  ver =~ "^3\.3\.[0-2]SG$" ||
  ver =~ "^3\.4\.[0-2]SG$"
)
  fixed_ver = "3.4.4SG";

else if (
  ver =~ "^3\.8\.[0-2]S$" ||
  ver =~ "^3\.9\.[01]S$" ||
  ver == "3.10.0S"
)
  fixed_ver = "3.10.4S";

if (isnull(fixed_ver)) audit(AUDIT_INST_VER_NOT_VULN, app, ver);


# RSVP check
override = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"^\s*(?:ip rsvp bandwidth|mpls traffic-eng tunnel)", string:buf)) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because RSVP is not enabled.");
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
