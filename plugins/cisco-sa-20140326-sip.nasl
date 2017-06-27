#TRUSTED 60a1e41d2e2ffa398cd0b4320bb9056d99b6016887ccdb9fe909673512ac4f863de303635b847e85713bf3633da25971194616575e16ccfd8e300969f5f1c0ed60060d92cc6b1269803cb223ae4daf37bfdb84cdaebbc71990d044d28138aa7ef31c29a3f1b63f2105242fb5083a6a0a0c05f6054e859b5354f591fdd67325a5c70f6618124a654fbfd99b6240031fbf333c50320a82ee267af67a6565e415912e84bba9aacd2c4dc543eea5de7af6851a3a8d39ab606a49e9906d5f1e58f6ca435046827c47a2bb835cdbe3526b7a6b117901b13354ee61829a16b712fd12ddd40aea3143c5f19be0a6ad1bf594cff9d6fb1949e3fe6ed8a7b9e747f92620bf864167a2bd41b8b54caa055b951df07c63f8206319f01f1286c27f951a603a64ca3d6146f885a7d70071d858c55420ceac6a482a96755f9df01787879c9200526798110c70eb19a2dcd5906383f3d70992f933429af203cf9337fe4af3351cb4a9f4081697f7887fed57ee65f5b260863c7a4af51367764c2d2b97fe285e3ca0ede5cb68b14b44e7c86974353dc1ed67372a751c4db9fb4b242e9461431eeeec8d98c0f14788f96c2e6ece9ba859530c750d49d7a88289a2a9ecfb7400caa5b9fe4130acb05581293a57f0436fbe4b823082fd0465cf3b90110a5da201704b159773a291da47b380daf896705a6cc984718f11d231fc371fb78ddd0c26613491
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73347);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/10/03");

  script_cve_id("CVE-2014-2106");
  script_bugtraq_id(66465);
  script_osvdb_id(104969);
  script_xref(name:"CISCO-BUG-ID", value:"CSCug45898");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140326-sip");

  script_name(english:"Cisco IOS Software Session Initiation Protocol Denial of Service (cisco-sa-20140326-sip)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS
running on the remote host is affected by a denial of service
vulnerability in the Session Initiation Protocol (SIP) implementation.
An unauthenticated, remote attacker could potentially exploit this
issue to cause a denial of service.

Note that this issue only affects hosts configured to process SIP
messages. SIP is not enabled by default on newer IOS versions.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140326-sip
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?63e67dcc");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20140326-sip.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/04");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
report = "";
cbi = "CSCug45898";
fixed_ver = "15.3(3)M2";

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");
if ( ver == '15.3(3)M' || ver == '15.3(3)M1') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    buf = cisco_command_kb_item("Host/Cisco/Config/show_processes", "show processes");
    if (check_cisco_result(buf))
    {
      if (
           (preg(multiline:TRUE, pattern:"CCSIP_UDP_SOCKET", string:buf)) ||
           (preg(multiline:TRUE, pattern:"CCSIP_TCP_SOCKET", string:buf))
         ) { flag = 1; }
    } else if (cisco_needs_enable(buf)) {flag = 1; override = 1; }
  }
}

if (flag)
{
  report +=
    '\n  Cisco Bug ID        : ' + cbi +
    '\n    Installed release : ' + ver +
    '\n    Fixed release     : ' + fixed_ver + '\n';
  security_hole(port:0, extra:report + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
