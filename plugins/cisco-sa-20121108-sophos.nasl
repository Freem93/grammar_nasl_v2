#TRUSTED 0c2897af59296372e0c3866899d2e2be5222f86f2640c033595be03f6d314c89e3da541c1a75b5b992e5a11dc75489e8a6d1668ef1a62728ea83ded7711c1aaf731f11d97ed70a55342c50cb2dd956fe0b96d7721729453c6e4dd02399296f2a9cdf941d6d0cc8a0d6510870f61783f6223a5fec4a8321ebacb2608ff2792177a197609ad3af65ffac9256916057ba7c670c9e49a6b65031ff2ee377f4167b5ed55b08aa9b6d1ec893f0117abcb69f14b5954409acd1eb248ece57b3c4ddcace99d7f16403a1bbf21b068ae13337980320151e45e51dc09722fc6c7e309da6210f005bb9fb2868587ed2b685d4697279b1676c5d0cfc7b319d1e18cc1ee2f2c5f1fb3e475a34add67207c5d9c475d557930132e98c2dc55f1ea528d39537b1e5da8833863a6794b8f89499fa2719a8b35ae925a9fa2568b59d09ad055a00470f698c9b477890bb0b448c63bac72a1d326943d1b7bfddb67245b9f6d2d39ed5728d1468564bb6f4ad205633dcffc2dd9a6eb91cc4384900ae801546afb37690be8f0280bb39c2cf3b385eaee32dba942ef3e2c2d082e93c06c9b62e71bb8c67b91b280ba69a5c95f91d6ce235cec4f97b2c12edc3e3b4f806fce8ed88bfcdce9e16e42f04e9564837fe46b8a7e02b63fee293659edf199205adbac69e14a9b07244ef54a16a2699144db181675498878cb68092c74e59d543cfdbd05198ee46a3
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70125);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/06/03");

  script_bugtraq_id(56401);
  script_osvdb_id(87056, 87057, 87058, 87059, 87060, 87061, 87062, 87063);
  script_xref(name:"CERT", value:"662243");
  script_xref(name:"CISCO-BUG-ID", value:"CSCud10546");
  script_xref(name:"CISCO-BUG-ID", value:"CSCud10556");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20121108-sophos");
  script_xref(name:"IAVA", value:"2012-A-0203");

  script_name(english:"Cisco IronPort Appliances Sophos Anti-Virus Vulnerabilities (cisco-sa-20121108-sophos)");
  script_summary(english:"Checks the Sophos Engine Version");

  script_set_attribute(attribute:"synopsis", value:
"The remote device uses an antivirus program that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IronPort appliance has a version of the Sophos
Anti-Virus engine that is 3.2.07.352_4.80 or earlier. It is,
therefore, reportedly affected by the following vulnerabilities :

  - An integer overflow exists when parsing Visual Basic 6
    controls.

  - A memory corruption issue exists in the Microsoft CAB
    parsers.

  - A memory corruption issue exists in the RAR virtual
    machine standard filters.

  - A privilege escalation vulnerability exists in the
    network update service.

  - A stack-based buffer overflow issue exists in the PDF
    file decrypter.

An unauthenticated, remote attacker could leverage these issues to
gain control of the system, escalate privileges, or cause a denial-of-
service.");
  script_set_attribute(attribute:"see_also", value:"https://lock.cmpxchg8b.com/sophailv2.pdf");
  script_set_attribute(attribute:"see_also", value:"http://www.sophos.com/en-us/support/knowledgebase/118424.aspx");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20121108-sophos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9e995f86");
  script_set_attribute(attribute:"solution", value:
"Update to Sophos engine version 3.2.07.363_4.83 as discussed in Cisco
Security Advisory cisco-sa-20121108-sophos.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:email_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sophos:sophos_anti-virus");

  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");
  script_require_ports("Host/AsyncOS/Cisco Email Security Appliance", "Host/AsyncOS/Cisco Web Security Appliance");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

version_cmd = get_kb_item("Host/AsyncOS/version_cmd");
if (isnull(version_cmd)) audit(AUDIT_OS_NOT, "Cisco AsyncOS");


version = NULL;
if (get_kb_item("Host/AsyncOS/Cisco Email Security Appliance"))
{
  sock_g = ssh_open_connection();
  if (!sock_g) exit(1, "Failed to open an SSH connection.");

  cmd = "antivirusstatus sophos";
  output = ssh_cmd(cmd:cmd+'\r\n', nosudo:TRUE, nosh:TRUE);

  ssh_close_connection();

  if ("SAV Engine Version" >< output)
  {
    match = eregmatch(pattern:"SAV Engine Version[ \t]+([0-9][0-9._]+)", string:output);
    if (isnull(match)) exit(1, "Failed to extract the SAV engine version.");
    version = match[1];
  }
  else if ("Unknown command or missing feature key" >< output)
  {
    exit(0, "The remote Cisco Email Security Appliance does not include a version of Sophos Anti-Virus.");
  }
  else
  {
    exit(1, "Unexpected output from running the command '"+cmd+"'.");
  }
}
else if (get_kb_item("Host/AsyncOS/Cisco Web Security Appliance"))
{
  if ("SAV Engine Version" >< version_cmd)
  {
    match = eregmatch(pattern:"SAV Engine Version[ \t]+([0-9][0-9._]+)", string:version_cmd);
    if (isnull(match)) exit(1, "Failed to extract the SAV engine version.");
    version = match[1];
  }
  else exit(0, "The remote Cisco Web Security Appliance does not include a version of Sophos Anti-Virus.");
}
else exit(0, "The host is not a Cisco IronPort ESA or WSA.");


# nb: Cisco's advisory says 3.2.07.352_4.80 and earlier are affected
#     but tells customers that version 3.2.07.363_4.83 fixes the issues.
recommended_version = NULL;
if (version =~ "^[0-9][0-9.]+_[0-9][0-9.]+$")
{
  version_num = str_replace(find:"_", replace:".", string:version);
  if (ver_compare(ver:version_num, fix:"3.2.07.352.4.80", strict:FALSE) <= 0) recommended_version = "3.2.07.363_4.83";
}
else if (version =~ "^[0-9][0-9.]+$")
{
  if (ver_compare(ver:version, fix:"4.80", strict:FALSE) <= 0) recommended_version = "4.83";
}
# These next two cases shouldn't happen.
else if (isnull(version)) exit(1, "Failed to identify if the remote Cisco IronPort appliance uses Sophos Anti-Virus.");
else exit(1, "Unrecognized format for the Sophos Anti-Virus engine version ("+version+") on the remote Cisco IronPort appliance.");


if (isnull(recommended_version)) audit(AUDIT_INST_VER_NOT_VULN, 'Sophos engine', version);

if (report_verbosity > 0)
{
  report =
    '\n  Sophos engine installed version   : '+ version +
    '\n  Sophos engine recommended version : '+ recommended_version +
    '\n';
  security_hole(port:0, extra:report);
}
else security_hole(0);
