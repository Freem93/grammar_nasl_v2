#TRUSTED 1e73b97b547944501ad3650634b040a0d62978731681e6666a5449b2656b159960863b81863005d6186ee04c7d8c01cae502799873df50847e8cd4b543665e167f523b06a772bb604ef6ec904bfb6696a2d3127ec1321edd28341095c9d08099f4a7b3465e67d1bf4c5274712509ec65da99c488dfd62c681c30c860dcd0171636162a3942032ca72b3d917504ee99a646ac2ce82b2bbdb79c807487fab769a9a1cb7fde9f2c8436c63fb301489ff2630153056f3bfc7b3e345be5be9cd969b20d91b2b34924d880dc91b55720a9a378a940b5f62d2595e75089bbaf16dba7c3564a8c5e126d1f090c3bfce2182e6bb156a95cba3fc38c38fb71fd1ef9afaec575c6886a1e607973c80f4ec0b39cb5a81f6d0025096e3816e0340e9da0963a05aaefc3ecf10f9db52c2416010dd43ec36669411d65e15ff9cde141a5cc1cf3a98ecdb76c7cf5e3cc9375da8ea49dc7a02f5a31457ffdf45f2b568d07db5a7e55d9598b6dc872e6aba3370827876832818705e028638c9d23fceb86c1e2256064096b6c8dc75f36e22fcddabe49e25ceff30f8686d4c49da6bc7a8221accb3dbd6f729a4b3bd4895625c6d98831bc9b3eb5577b1cd3c8fc6a1569906999717945a4481bd8d0c4cc04e4caf947b37000ba700cd64af95de21e36da96b865e02ea77b86c114cfff1b547ad2c4eee38598c4c904bc277cc0774a1bd3697262400f4d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85229);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2015-5362");
  script_bugtraq_id(75721);
  script_osvdb_id(124299);
  script_xref(name:"JSA", value:"JSA10690");

  script_name(english:"Juniper Junos bfdd RCE (JSA10690)");
  script_summary(english:"Checks the Junos version and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a remote code execution vulnerability in
the BFD daemon (bfdd). A remote attacker, using a specially crafted
BFD packet, can exploit this to cause a denial of service or execute
arbitrary code.

Note that this issue only affects devices with the BFD daemon running.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10690");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10690.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/04");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

fixes = make_array();

fixes['12.1X44'] = '12.1X44-D50';
fixes['12.1X46'] = '12.1X46-D35';
fixes['12.1X47'] = '12.1X47-D25';
fixes['12.3']    = '12.3R10';
fixes['12.3X48'] = '12.3X48-D15';
fixes['13.2']    = '13.2R8';
fixes['13.3']    = '13.3R6';
fixes['14.1']    = '14.1R5';
fixes['14.1X50'] = '14.1X50-D85';
fixes['14.1X55'] = '14.1X55-D20';
fixes['14.2']    = '14.2R3';
fixes['15.1']    = '15.1R1';
fixes['15.1X49'] = '15.1X49-D10';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = TRUE;
buf = junos_command_kb_item(cmd:"show system processes");
if (buf)
{
  if (!junos_check_config(buf:buf, pattern:" /usr/sbin/bfdd "))
    audit(AUDIT_HOST_NOT, 'affected because the BFD daemon is not running');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
