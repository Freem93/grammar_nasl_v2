#TRUSTED 25d1821072b159af61fa7f7e11766dea9a6de02fd9f1ff227a490df5577565646d935c02a3e8243ee8c99f5ddd08afa331bbddae95faf659c82c13110cc98938fc89f2bf733fa0a35b6ba31b99b0fe968c3c78dd52d4e97ca794bfe13d7d9eebe16da249218f5591e2f1e6a0d5ec6f7d17d1c5bfca20c74e8b5c96b11f165ed04aa7bfe6372a3566ec46c9078c53afe53ce4ed9fef3f38464748ffe02aaa32929b361e1797105c06828d4da44b9cfa4357691ba4cbc44a660e43c1149facf1b3c7031a810c25eb21cac9945586be5231ffd8f62ef2c060b8323bb6f00bbfad5b69c309e39bd3ce15e28b2ecc8cd95666e2bdc5a1eb6eeeced7e2bbbbd5ec97089b195f7f7a89bdc07fdd353cbe47deb6e4e09b8c6c8c4c9ab89fed2bb9c84bd9a04544d28ab79a47adab550711b18e5b1363561d676380b454bd8e115f3e73770dbb20c5fbf64cab6f036db5c491cca82f4c341ab4dccd9e8419269ccd5912370157dbd3a969c1656c31054f00114144ba691d8e1220a7832de2709e6cd30bfcd2b08ddc21226cdd2cbbcc94dce9036513349a9f99dd354400f26006821b72fdadc7d14f9d650770275e0928251ccab74b7836b7aafdb0c110727300bcf0cb5ae66613b3a4483c1031c9b68017babb9593c4dc6abcdf2cc341268952692ea930c29b8126a60f2440db28764ec22cb1692890a2e74037a983f9e636b060616b23
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90358);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/05/26");

  script_cve_id("CVE-2016-1349");
  script_osvdb_id(136244);
  script_xref(name:"TRA", value:"TRA-2016-04");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuv45410");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160323-smi");

  script_name(english:"Cisco IOS Smart Install Packet Image List Parameter Handling DoS (cisco-sa-20160323-smi)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS software running
on the remote device is affected by a denial of service vulnerability
in the Smart Install client feature due to improper handling of image
list parameters. An unauthenticated, remote attacker can exploit this
issue, via crafted Smart Install packets, to cause the device to
reload.");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

# Check for vuln version
if ( ver == '12.2(35)EX' ) flag++;
if ( ver == '12.2(35)EX1' ) flag++;
if ( ver == '12.2(35)EX2' ) flag++;
if ( ver == '12.2(37)EX' ) flag++;
if ( ver == '12.2(40)EX' ) flag++;
if ( ver == '12.2(40)EX1' ) flag++;
if ( ver == '12.2(40)EX2' ) flag++;
if ( ver == '12.2(40)EX3' ) flag++;
if ( ver == '12.2(44)EX' ) flag++;
if ( ver == '12.2(44)EX1' ) flag++;
if ( ver == '12.2(46)EX' ) flag++;
if ( ver == '12.2(52)EX' ) flag++;
if ( ver == '12.2(52)EX1' ) flag++;
if ( ver == '12.2(53)EX' ) flag++;
if ( ver == '12.2(55)EX' ) flag++;
if ( ver == '12.2(55)EX1' ) flag++;
if ( ver == '12.2(55)EX2' ) flag++;
if ( ver == '12.2(55)EX3' ) flag++;
if ( ver == '12.2(58)EX' ) flag++;
if ( ver == '12.2(37)EY' ) flag++;
if ( ver == '12.2(44)EY' ) flag++;
if ( ver == '12.2(46)EY' ) flag++;
if ( ver == '12.2(53)EY' ) flag++;
if ( ver == '12.2(55)EY' ) flag++;
if ( ver == '12.2(58)EY' ) flag++;
if ( ver == '12.2(58)EY1' ) flag++;
if ( ver == '12.2(58)EY2' ) flag++;
if ( ver == '12.2(53)EZ' ) flag++;
if ( ver == '12.2(55)EZ' ) flag++;
if ( ver == '12.2(58)EZ' ) flag++;
if ( ver == '12.2(60)EZ' ) flag++;
if ( ver == '12.2(60)EZ1' ) flag++;
if ( ver == '12.2(60)EZ2' ) flag++;
if ( ver == '12.2(60)EZ3' ) flag++;
if ( ver == '12.2(60)EZ4' ) flag++;
if ( ver == '12.2(60)EZ5' ) flag++;
if ( ver == '12.2(60)EZ6' ) flag++;
if ( ver == '12.2(60)EZ7' ) flag++;
if ( ver == '12.2(60)EZ8' ) flag++;
if ( ver == '12.2(25)FZ' ) flag++;
if ( ver == '12.2(35)SE' ) flag++;
if ( ver == '12.2(35)SE1' ) flag++;
if ( ver == '12.2(35)SE2' ) flag++;
if ( ver == '12.2(35)SE3' ) flag++;
if ( ver == '12.2(35)SE4' ) flag++;
if ( ver == '12.2(35)SE5' ) flag++;
if ( ver == '12.2(37)SE' ) flag++;
if ( ver == '12.2(37)SE1' ) flag++;
if ( ver == '12.2(40)SE' ) flag++;
if ( ver == '12.2(40)SE1' ) flag++;
if ( ver == '12.2(40)SE2' ) flag++;
if ( ver == '12.2(44)SE' ) flag++;
if ( ver == '12.2(44)SE1' ) flag++;
if ( ver == '12.2(44)SE2' ) flag++;
if ( ver == '12.2(44)SE3' ) flag++;
if ( ver == '12.2(44)SE4' ) flag++;
if ( ver == '12.2(44)SE5' ) flag++;
if ( ver == '12.2(44)SE6' ) flag++;
if ( ver == '12.2(46)SE' ) flag++;
if ( ver == '12.2(46)SE1' ) flag++;
if ( ver == '12.2(46)SE2' ) flag++;
if ( ver == '12.2(50)SE' ) flag++;
if ( ver == '12.2(50)SE1' ) flag++;
if ( ver == '12.2(50)SE2' ) flag++;
if ( ver == '12.2(50)SE3' ) flag++;
if ( ver == '12.2(50)SE4' ) flag++;
if ( ver == '12.2(50)SE5' ) flag++;
if ( ver == '12.2(52)SE' ) flag++;
if ( ver == '12.2(52)SE1' ) flag++;
if ( ver == '12.2(53)SE' ) flag++;
if ( ver == '12.2(53)SE1' ) flag++;
if ( ver == '12.2(53)SE2' ) flag++;
if ( ver == '12.2(54)SE' ) flag++;
if ( ver == '12.2(55)SE' ) flag++;
if ( ver == '12.2(55)SE1' ) flag++;
if ( ver == '12.2(55)SE10' ) flag++;
if ( ver == '12.2(55)SE2' ) flag++;
if ( ver == '12.2(55)SE3' ) flag++;
if ( ver == '12.2(55)SE4' ) flag++;
if ( ver == '12.2(55)SE5' ) flag++;
if ( ver == '12.2(55)SE6' ) flag++;
if ( ver == '12.2(55)SE7' ) flag++;
if ( ver == '12.2(55)SE8' ) flag++;
if ( ver == '12.2(55)SE9' ) flag++;
if ( ver == '12.2(58)SE' ) flag++;
if ( ver == '12.2(58)SE1' ) flag++;
if ( ver == '12.2(58)SE2' ) flag++;
if ( ver == '12.2(25)SED' ) flag++;
if ( ver == '12.2(25)SED1' ) flag++;
if ( ver == '12.2(25)SEE' ) flag++;
if ( ver == '12.2(25)SEE1' ) flag++;
if ( ver == '12.2(25)SEE2' ) flag++;
if ( ver == '12.2(25)SEE3' ) flag++;
if ( ver == '12.2(25)SEE4' ) flag++;
if ( ver == '12.2(25)SEF1' ) flag++;
if ( ver == '12.2(25)SEF2' ) flag++;
if ( ver == '12.2(25)SEF3' ) flag++;
if ( ver == '12.2(25)SEG' ) flag++;
if ( ver == '12.2(25)SEG1' ) flag++;
if ( ver == '12.2(25)SEG2' ) flag++;
if ( ver == '12.2(25)SEG3' ) flag++;
if ( ver == '12.2(25)SEG4' ) flag++;
if ( ver == '12.2(25)SEG5' ) flag++;
if ( ver == '12.2(25)SEG6' ) flag++;
if ( ver == '15.0(2)EB' ) flag++;
if ( ver == '15.0(2)EC' ) flag++;
if ( ver == '15.0(2)ED' ) flag++;
if ( ver == '15.0(2)ED1' ) flag++;
if ( ver == '15.0(2)EH' ) flag++;
if ( ver == '15.0(2)EJ' ) flag++;
if ( ver == '15.0(2)EJ1' ) flag++;
if ( ver == '15.0(2)EK' ) flag++;
if ( ver == '15.0(2)EK1' ) flag++;
if ( ver == '15.0(1)EX' ) flag++;
if ( ver == '15.0(2)EX' ) flag++;
if ( ver == '15.0(2)EX1' ) flag++;
if ( ver == '15.0(2)EX2' ) flag++;
if ( ver == '15.0(2)EX3' ) flag++;
if ( ver == '15.0(2)EX4' ) flag++;
if ( ver == '15.0(2)EX5' ) flag++;
if ( ver == '15.0(2)EX8' ) flag++;
if ( ver == '15.0(2a)EX5' ) flag++;
if ( ver == '15.0(1)EY' ) flag++;
if ( ver == '15.0(1)EY1' ) flag++;
if ( ver == '15.0(1)EY2' ) flag++;
if ( ver == '15.0(2)EY' ) flag++;
if ( ver == '15.0(2)EY1' ) flag++;
if ( ver == '15.0(2)EY2' ) flag++;
if ( ver == '15.0(2)EY3' ) flag++;
if ( ver == '15.0(2)EZ' ) flag++;
if ( ver == '15.0(1)SE' ) flag++;
if ( ver == '15.0(1)SE1' ) flag++;
if ( ver == '15.0(1)SE2' ) flag++;
if ( ver == '15.0(1)SE3' ) flag++;
if ( ver == '15.0(2)SE' ) flag++;
if ( ver == '15.0(2)SE1' ) flag++;
if ( ver == '15.0(2)SE2' ) flag++;
if ( ver == '15.0(2)SE3' ) flag++;
if ( ver == '15.0(2)SE4' ) flag++;
if ( ver == '15.0(2)SE5' ) flag++;
if ( ver == '15.0(2)SE6' ) flag++;
if ( ver == '15.0(2)SE7' ) flag++;
if ( ver == '15.2(1)E' ) flag++;
if ( ver == '15.2(1)E1' ) flag++;
if ( ver == '15.2(1)E2' ) flag++;
if ( ver == '15.2(1)E3' ) flag++;
if ( ver == '15.2(2)E' ) flag++;
if ( ver == '15.2(2)E1' ) flag++;
if ( ver == '15.2(2)E2' ) flag++;
if ( ver == '15.2(2)E3' ) flag++;
if ( ver == '15.2(2a)E1' ) flag++;
if ( ver == '15.2(2a)E2' ) flag++;
if ( ver == '15.2(3)E' ) flag++;
if ( ver == '15.2(3)E1' ) flag++;
if ( ver == '15.2(3)E2' ) flag++;
if ( ver == '15.2(3a)E' ) flag++;
if ( ver == '15.2(3m)E2' ) flag++;
if ( ver == '15.2(3m)E3' ) flag++;
if ( ver == '15.2(2)EB' ) flag++;
if ( ver == '15.2(2)EB1' ) flag++;
if ( ver == '15.2(1)EY' ) flag++;
if ( ver == '15.2(2)EA1' ) flag++;
if ( ver == '15.2(2)EA2' ) flag++;
if ( ver == '15.2(3)EA' ) flag++;

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
