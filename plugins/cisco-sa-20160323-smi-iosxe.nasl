#TRUSTED 072298f4a26aae25a8d41e153cae3a5ded10991e21c28ccf48aea1d9f904ae116e5df83b369dbf395d5ca36bb7a9cd02492aff4f9190661fbb298a69f1f1d3b00d50360652ebcfb80dec4637f9286908ab55e2c3f0f231fafcb5f4974f7a9bf05e47c760c345921d0e44d79534668fb0561a972cd51a24d5a709d456f336180ba04ecd99bcc2829ffded903dd7fe119c09be5baa5c2582911d3ae245f36244510b4f465b221db06f55e2fa9db42f933c4d574fdecd500492bba8ac17abf6f318453c72e0284728cbd422b8fac7c8165a0e9011b40013fd27a01c95183a217dcc56c431d0f0841c36bf1c8d95bc9ec5185e634af4837c76294a1e493df4ff2bcc49dc2ee44a72a612b9298bee816dabd34ad4cdba43e4b174d792f3a410c486a3a64ff4b336a9d929be038114b5f730696acd5dc29bdf396b1b7780c0257c5c6e8920ba5a750bcf52cfec2905cb9144b4bc4cf1051dde2b733e34870dd0daf8e7a8a71962448b798f035897c8c9bbfeedb8275732b34eed915a621811c0dd92331fd9074676c9b7929c3b6e534990fae4b9b18ba6230dcc7731d8eb50696bebc65042e59bd08dd83d54a62a436a4ec9681f1c2bec446c9900bcd4fbd169ee7159530bae52b622954827c721b3ff13755233790b893338dd0b81616e3641e62019bff38b1df40e5bcd91d48dd11efc34facb058d8d5f64b6332c10102a55db4c16
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90359);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/05/26");

  script_cve_id("CVE-2016-1349");
  script_osvdb_id(136244);
  script_xref(name:"TRA", value:"TRA-2016-04");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuv45410");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160323-smi");

  script_name(english:"Cisco IOS XE Smart Install Packet Image List Parameter Handling DoS (cisco-sa-20160323-smi)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is affected by a denial of service
vulnerability in the Smart Install client feature due to improper
handling of image list parameters. An unauthenticated, remote attacker
can exploit this issue, via crafted Smart Install packets, to cause
the device to reload.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160323-smi
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8f6c97e2");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2016-04");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuv45410. Alternatively, disable the Smart Install feature per the
vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

flag = 0;
override = 0;

# Check for vuln version
if ( ver == '3.2.0JA' ) flag++;
if ( ver == '3.2.0SE' ) flag++;
if ( ver == '3.2.1SE' ) flag++;
if ( ver == '3.2.2SE' ) flag++;
if ( ver == '3.2.3SE' ) flag++;
if ( ver == '3.3.0SE' ) flag++;
if ( ver == '3.3.1SE' ) flag++;
if ( ver == '3.3.2SE' ) flag++;
if ( ver == '3.3.3SE' ) flag++;
if ( ver == '3.3.4SE' ) flag++;
if ( ver == '3.3.5SE' ) flag++;
if ( ver == '3.3.0XO' ) flag++;
if ( ver == '3.3.1XO' ) flag++;
if ( ver == '3.3.2XO' ) flag++;
if ( ver == '3.4.0SG' ) flag++;
if ( ver == '3.4.1SG' ) flag++;
if ( ver == '3.4.2SG' ) flag++;
if ( ver == '3.4.3SG' ) flag++;
if ( ver == '3.4.4SG' ) flag++;
if ( ver == '3.4.5SG' ) flag++;
if ( ver == '3.4.6SG' ) flag++;
if ( ver == '3.5.0E' ) flag++;
if ( ver == '3.5.1E' ) flag++;
if ( ver == '3.5.2E' ) flag++;
if ( ver == '3.5.3E' ) flag++;
if ( ver == '3.6.0E' ) flag++;
if ( ver == '3.6.1E' ) flag++;
if ( ver == '3.6.2aE' ) flag++;
if ( ver == '3.6.2E' ) flag++;
if ( ver == '3.7.0E' ) flag++;
if ( ver == '3.7.1E' ) flag++;
if ( ver == '3.7.2E' ) flag++;

# Check for Smart Install client feature
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_vstack_config", "show vstack config");
  if (check_cisco_result(buf))
  {
    if ( (preg(multiline:TRUE, pattern:"Role:\s*[Cc]lient", string:buf)) &&
         (!preg(multiline:TRUE, pattern:"Role:\s*[Cc]lient\s+\(SmartInstall disabled\)", string:buf)) ) { flag = 1; }
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCuv45410' +
      '\n  Installed release : ' + ver +
      '\n';
    security_hole(port:0, extra:report + cisco_caveat(override));
    exit(0);
  }
  else security_hole(port:0, extra:cisco_caveat(override));
}
else audit(AUDIT_HOST_NOT, "affected");
