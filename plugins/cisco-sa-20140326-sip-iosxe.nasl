#TRUSTED 3c8284ec9e35c4f92e6a2b69d7e4d5b920fd384aafae5e62fa9f46ea4434bc1a157d837844b47e3501b3335a548c7748b386c5e1a156f906f43c9956691349466109d3f18bbb6e5761eb502519bbf0a8858980d94a640dcac8b26b7fa65d470468a2ce38e2d149e8499368fd699f662e8b63af3d396c3a85dc7ebd52d6fc07e4cc40998bd78c7d8533c9ff58ff920373fd77dee3c136b75e0215be561344f865ab0f35b03e13a644b5f7597893cffc62f2de25bb8f5d65da963396dee2b7a053de1ecf8156014ab9d9b11e919b6235b677905f34f1b02956038a9121a16ac3f7f9e9d5422e2921bdca1c54cb87e6487755961b9e55c3f91e548657aa63a8b029745c0c4a9e9cc4039f60dec41bed72e5c77a8c26893404f9060fb42eee4c7320a7d6b5472bac86f07e936c1f93a3254dc81f6fe746db5a3e26d28ad586027b96cff8ac322794e1b014586538ed36bcbb9e7e9294802d908a5a263edb2f397e7d9a495130073665b34d411e6f9445c5d9ab0c6bd21e9831e460e20edec8c80f4205b4f0c3f80f447bbea52781fa97a69d39e349ba7455db32cb6baf60ff9a27da601f03042859032ad367e1d4f4f95109c671e27e78ccac41b556229b92b0254e16efb5459d576af7b6af072684e4eee02a2af6846a625c3d7fecacf1cac35fa6c7d6292cc6ba74f88b55685dab913e3b42ca7823804e43b571df2fe9245c542e
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73346);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/10/03");

  script_cve_id("CVE-2014-2106");
  script_bugtraq_id(66465);
  script_osvdb_id(104969);
  script_xref(name:"CISCO-BUG-ID", value:"CSCug45898");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140326-sip");

  script_name(english:"Cisco IOS XE Software Session Initiation Protocol Denial of Service (cisco-sa-20140326-sip)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS XE
running on the remote host is affected by a denial of service
vulnerability in the Session Initiation Protocol (SIP) implementation.
An unauthenticated, remote attacker could potentially exploit this
issue to cause a denial of service.

Note that this issue only affects hosts configured to process SIP
messages. SIP is not enabled by default on newer IOS XE versions.");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/04");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}


include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;
report = "";
cbi = "CSCug45898";
fixed_ver = "3.10.2S";

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

if (ver == '3.10.0S' || ver == '3.10.0aS' || ver == '3.10.1S') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_processes", "show processes");
    if (check_cisco_result(buf))
    {
      if (
           (preg(multiline:TRUE, pattern:"CCSIP_UDP_SOCKET", string:buf)) ||
           (preg(multiline:TRUE, pattern:"CCSIP_TCP_SOCKET", string:buf))
         ) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
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
