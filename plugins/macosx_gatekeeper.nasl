#TRUSTED 90381facbd0bcbd5c370a4a012816252a70ae6db5c26649af640e4278822a9e7758abd9f4c3b11a53bc75a42eb9024ac8f04ec19eab5fa543f122b30940f0a8f3995e7a1a6ed1702bc18f7c4510e553c6908aa74d9feca3df0c3257571b9bfd805980165682c519ac51a061d5f43771d97873bddfa4b31e20c315fe2ecc6d3d50f16aa497a019c8a7512b342e4126f29e96ed1f78e27e70b6476586382f3598c3ef05d8f1d760c981066d79a4d27b08e6190e109b057ce7376d355e9dcf05e9d6352d6d83b33bc0058c259b11c3d15567628fc230eb9b8a68bd6e0724147259d4e425fe4ddfed3c32462c6269af8fa518163b129ab85dcfa2182984abd53c9f889aa8c035b1c75f1171f47734c6df55285b93b6c4c91bf314fe87bd8054bb58f6d680bd047279f8a5d70dc7c69cfa1becc623e76145af51938989f2acbce01195e9c347abb9bb6f55a7b0e84657327250428731dcb3ce32ea7642f3118a56d1a38916f97fc08505654b68a7ce52c2c3c34c59436262e67560825043e86d81cc945a8b24ea918fe7525d0791716eb6d6e0853bfbd5d956c90e3f63a1218eff841ccee4a10022d759a319ecf71e3cc9c63d5030e1db8602561fadfe87d9ece1eac021cc61397a63c2cd7153cbb1eb5e681b09f21eea3abb7eb440a726f197a509933ff1aca0f2449d838c2e15c044b0e0c36a8f7611a0f1ba2be28f33d466c7e93
#
# (C) Tenable Network Security, Inc.
#
include("compat.inc");

if (description)
{
  script_id(89924);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/03/14");

  script_name(english:"Mac OS X Gatekeeper Disabled");
  script_summary(english:"Checks that Gatekeeper is enabled.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host has Gatekeeper disabled.");
  script_set_attribute(attribute:"description", value:
"Mac OS X Gatekeeper, a protection service that guards against
untrusted software, is disabled on the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-ca/HT202491");
  script_set_attribute(attribute:"solution", value:
"Ensure that this use of Gatekeeper is in accordance with your security
policy.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");

if (!get_kb_item("Host/local_checks_enabled"))
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item("Host/MacOSX/Version");
if (!os)
  audit(AUDIT_OS_NOT, "Mac OS X");

extract = eregmatch(pattern:"^Mac OS X ([\d.]+)$", string:os);
if (!isnull(extract))
  version = extract[1];
else
  exit(1, "Error extracting Mac OS X version.");

# Gatekeeper arrived in OS X 10.7.5
 # audit-trail:success: The remote host's OS is Mac OS X 10.7.5, which is required for Gatekeeper, not Mac OS X 10.7.4.
if (ver_compare(ver:version, fix:"10.7.5", strict:FALSE) < 0)
  audit(AUDIT_OS_NOT, "Mac OS X 10.7.5, which is required for Gatekeeper", os);

cmd = 'spctl --status';

res = exec_cmd(cmd:cmd);

if ( "assessments enabled" >!< res && "assessments disabled" >!< res)
  exit(1, "Unexpected output from '" + cmd + "'.");

if ( "assessments enabled" >< res )
{
  set_kb_item(name:"Host/MacOS/Gatekeeper/enabled", value:TRUE);
  exit(0, "Gatekeeper is enabled.");
}
else
{
  report = '\n  Mac OS X Gatekeeper is disabled. Ensure this is in accordance' +
           '\n  with your security policy.' +
           '\n';
  security_report_v4(port:0, extra:report, severity:SECURITY_NOTE);
  exit(0);
}
