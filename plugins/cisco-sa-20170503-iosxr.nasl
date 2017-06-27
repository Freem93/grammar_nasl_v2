#TRUSTED 67806b190ba0eae2cd156c808c6adf192a2fed3b2fda81d1fb7ec16afc3fd0aff189c7dfdf8a831b3c1574eaccdf34ced47c6d969e8edab05734f57916541d2de8ed95b416a67dfb597bb96a7f09bcee1e8b5bdf08001f34d99b0185cb175bced550c21dcbf07ecf540a95871c186341a0752ec82b289d066b764d03220a69c4d5e294368f80aeacc48817ab82fda4cc001b7a6eb5788213b4b5faa1274accc47f2809c1ae3e1e464fceea953391325bf66cdfe426fa8f98a79f55d8d0fc5617e741fcac2a3c0ed040db97bf7fbcaa01e237a73e960db894fa7e6367efb6b3924da2f1f68598d8ed9bc3db5ce8e1bcfab3ae2c34a29babdf29076fbe96f2ec396b342eff75dcf00f8c75df9ee12cf9d2f9c994175a49b85d6651cc5d312d856084ce8381882603e738909c6be4f21d4f087aab9681568996672f6145fee8bc2dd1618001f83c829606b2fa22c0d5e44e4aeb64db6c3cf0ecb248c1ec750d758de26313c52b6ab93fd9a1a52ab6b8c0af51ae7018bfa0a9ba0f9783bf455ad6cad11594ae6edd66dcb5fda81bb7d7f5735c3e1094d97c541f29a9b4917c72ea6c5f72912a1c7be2e5a89fdeeb6f4f269ab0484531afaaa4b2fee0822af563ed1bd5da0e1897b31a3748411c445c11356b47f06da686194e35df5d2f8056704113b691e3c495169cc4dcb13bdeb11de49262c30e7778eee942543daf59288bb5c9
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99981);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/04");

  script_cve_id("CVE-2017-3876");
  script_bugtraq_id(98284);
  script_osvdb_id(156925);

  script_xref(name:"CISCO-BUG-ID", value:"CSCvb14441");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170503-ios-xr");

  script_name(english:"Cisco IOS XR Software Event Management Service gRPC Handling DoS (cisco-sa-20170503-ios-xr)");
  script_summary(english:"Checks the IOS XR version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco
IOS XR software running on the remote device is affected by a denial
of service vulnerability in the Event Management Service daemon (emsd)
due to improper handling of gRPC requests. An unauthenticated, remote
attacker can exploit this, by repeatedly sending unauthenticated gRPC
requests, to crash the device in such a manner than manual
intervention is required to recover.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170503-ios-xr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?716c8dcf");
  # http://www.networkworld.com/article/3194146/cisco-subnet/cisco-drops-critical-security-warning-on-vpn-router-3-high-priority-caveats.html#tk.rss_security
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fb25ecbb");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb14441");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvb14441.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version  = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");

cmds = make_list();

flag = 0;
override = 0;

# Known Affected: 6.1.0 and 6.1.1 with gRPC service enabled and configured
if ((version == "6.1.1" || version == "6.1.0")
  && get_kb_item("Host/local_checks_enabled"))
{
  buf = cisco_command_kb_item("Host/Cisco/Config/show_run_include_grpc", "show run | include grpc");
  if (check_cisco_result(buf))
  {
    if ("grpc" >< buf && "!" >< buf)
    {
      cmds = make_list(cmds, "show run | include grpc");
      flag = 1;
    }
  }
  else if (cisco_needs_enable(buf))
    override = 1;

  if (!flag && !override) audit(AUDIT_OS_CONF_NOT_VULN, "Cisco IOS XR", version);
}

if (flag || override)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    override : override,
    version  : version,
    bug_id   : "CSCvb14441",
    cmds     : cmds
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
