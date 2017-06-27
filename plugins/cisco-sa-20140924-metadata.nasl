#TRUSTED 13163e393323738485146da7aa3002430c202e575f518e9617eea86807188a5b5272f87d6d6cd4bf464ea01279f8be915afaee99de209779f9e2e57201b2d1950e04b921be04b9e308a59fa201e4e4190a054f44869bccd54ed5db5faa0bd9a158808199c148cbee6b24244c14633d6fcde6a492551af20ea1d3b37e0478d25c0765293bb11c46a7f6e80b2738b17e5ddb0a5f427c3c179e11f890ab4501a51e70a968ea502c3d1cb334b0b5050fb06ad09b5a632355f642066d73ccfe62a1c2715310e25fe1ee98176538f9d696e2f8c4d5c819d951a13a1a154094d738f97cf5aaaafe4399334a827738743be62abf069c6b55eb28b551bf42dd3ee87009d406ac8a657f5c50305a6821078f7595897d510b036516de5d60089bb09709e2525dd4f8fa61379e32f4505bfeaa947af382df97a323075168fcb2a1611ead532e560786584a5657a57ca590b8f8f8435311b961603bfce8b2b49756e4c9a006c0228d98dbb96a4ee4a321e0e074c5bf20418bc6add1d7eff7bba810785f993108dd195f7177b21e356f0371f780c70a158be4fdadfe3b55879ff9f44c85bfdba99ecb4be46bb272b459e00c39aab5020f89cc857dc94f17c3846db5363a90f1913da2905329b13e8dcad190f9937ca3733d4358988c7f1bf8ac14934dd585c31138b7e42a1db4b340277485330aa9d6c0ae0142ccfc9e05d10a96cd2f32c71703
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78033);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-3355", "CVE-2014-3356");
  script_bugtraq_id(70130, 70135);
  script_osvdb_id(112038, 112039);
  script_xref(name:"CISCO-BUG-ID", value:"CSCue22753");
  script_xref(name:"CISCO-BUG-ID", value:"CSCug75942");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140924-metadata");

  script_name(english:"Cisco IOS Software Multiple IPv6 Metadata Flow Vulnerabilities (cisco-sa-20140924-metadata)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS
running on the remote host is affected by two vulnerabilities in the
IPv6 metadata flow feature due to improper handling of RSVP packets. A
remote attacker can exploit this issue by sending specially crafted
RSVP flows to cause the device to reload.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140924-metadata
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5eeb7284");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=35622");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=35623");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCue22753");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCug75942");

  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20140924-metadata.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/02");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

app = "Cisco IOS";
cbi = "CSCue22753 and CSCug75942";
fixed_ver = NULL;

#15.1SY
if (ver == "15.1(1)SY" || ver == "15.1(1)SY1")
  fixed_ver = "15.1(1)SY4 or 15.1(2)SY4";
else if (ver == "15.1(1)SY2" || ver == "15.1(1)SY3" || ver == "15.1(2)SY" || ver == "15.1(2)SY1" || ver == "15.1(2)SY2" || ver == "15.1(2)SY3")
{
  fixed_ver = "15.1(1)SY4 or 15.1(2)SY4";
  cbi = "CSCue22753";
}
#15.2GC
else if (ver == "15.2(1)GC" || ver == "15.2(1)GC1" || ver == "15.2(1)GC2" || ver == "15.2(2)GC" || ver == "15.2(3)GC" || ver == "15.2(3)GC1")
  fixed_ver = "15.2(4)M7";
else if (ver == "15.2(4)GC" || ver == "15.2(4)GC1" || ver == "15.2(4)GC2")
{
  fixed_ver = "15.2(4)M7";
  cbi = "CSCue22753";
}
#15.2GCA
else if (ver == "15.2(3)GCA" || ver == "15.2(3)GCA1")
  fixed_ver = "15.4(1)T";
#15.2M
else if (ver == "15.2(4)M" || ver == "15.2(4)M1" || ver == "15.2(4)M2" || ver == "15.2(4)M3")
  fixed_ver= "15.2(4)M7";
else if (ver == "15.2(4)M4" || ver == "15.2(4)M5" || ver == "15.2(4)M6" || ver == "15.2(4)M6b")
{
  fixed_ver = "15.2(4)M7";
  cbi = "CSCue22753";
}
#15.2S
else if (ver == "15.2(2)S" || ver == "15.2(2)S1" || ver == "15.2(4)S" || ver == "15.2(4)S1" || ver == "15.2(4)S2" || ver == "15.2(4)S3")
  fixed_ver = "15.2(2)S0a, 15.2(2)S2, 15.2(4)S0c, 15.2(4)S1c, 15.2(4)S2t, 15.2(4)S3a, or 15.2(4)S4";
#15.2T
else if (ver == "15.2(1)T" || ver == "15.2(1)T1" || ver == "15.2(1)T2" || ver == "15.2(1)T3" || ver == "15.2(1)T3a" || ver == "15.2(1)T4" || ver == "15.2(2)T" || ver == "15.2(2)T1" || ver == "15.2(2)T2" || ver == "15.2(2)T3" || ver == "15.2(2)T4" || ver == "15.2(3)T" || ver == "15.2(3)T1" || ver == "15.2(3)T2" || ver == "15.2(3)T3")
  fixed_ver = "15.2(4)M7";
else if (ver == "15.2(3)T4")
{
  fixed_ver = "15.2(4)M7";
  cbi = "CSCue22753";
}
#15.2XA
else if (ver == "15.2(3)XA")
  fixed_ver = "15.2(4)M7";
#15.2XB
else if (ver == "15.2(4)XB10")
  fixed_ver = "15.2(4)XB11";
#15.3M
else if (ver == "15.3(3)M" || ver == "15.3(3)M1" || ver == "15.3(3)M2" || ver == "15.3(3)M3")
{
  fixed_ver = "15.2(4)XB11";
  cbi = "CSCue22753";
}
#15.3S
else if (ver == "15.3(1)S" || ver == "15.3(1)S1" || ver == "15.3(2)S" || ver == "15.3(2)S0xa" || ver == "15.3(2)S1")
  fixed_ver = "15.3(1)S1e, 15.3(1)S2, 15.3(2)S1b, 15.3(2)S2, 15.3(3)S0b, 15.3(3)S1a, 15.3(3)S2a, or 15.3(3)S4";
else if (ver == "15.3(2)S0a" || ver == "15.3(3)S" || ver == "15.3(3)S1" || ver == "15.3(3)S2" || ver == "15.3(3)S3")
{
  fixed_ver = "15.3(1)S1e, 15.3(1)S2, 15.3(2)S1b, 15.3(2)S2, 15.3(3)S0b, 15.3(3)S1a, 15.3(3)S2a, or 15.3(3)S4";
  cbi = "CSCue22753";
}
#15.3T
else if (ver == "15.3(1)T" || ver == "15.3(1)T1" || ver == "15.3(2)T")
  fixed_ver = "15.3(2)T4";
else if (ver == "15.3(1)T2" || ver == "15.3(1)T3" || ver == "15.3(1)T4" || ver == "15.3(2)T1" || ver == "15.3(2)T2" || ver == "15.3(2)T3")
{
  fixed_ver = "15.3(2)T4";
  cbi = "CSCue22753";
}

if (isnull(fixed_ver)) audit(AUDIT_INST_VER_NOT_VULN, app, ver);


override = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  # metadata flow check
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"^\s*metadata flow$", string:buf)) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override)
  {
    # IPv6 metadata flow check
    buf = cisco_command_kb_item("Host/Cisco/Config/show_metadata_flow_table_ipv6", "show metadata flow table ipv6");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"^Flow\s+Proto\s+DPort\s+SPort", string:buf)) flag = TRUE;
    }
    else if (cisco_needs_enable(buf)) override = TRUE;
  }

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because the metadata flow feature is not enabled.");
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
