#TRUSTED 7792db82cf9753fffb47569bfa1f3c6497d86739b796d84a3185523a318085cf41d3d68d7c3bed5b066b95952e6ce1bd566c9f895691f62aae8cd137a85360dec5d1e7d33d68ce57ef464cabead1e0e06c3e0cec538404cafe6f3f3f7196e3546e83f26f4f6d05fad9b3ffb712e427da05eca7105ee84c82390000dcebfff52a512b752bca57d7d510d30e30d69ab62afb8bcd2a34ed0d7e36a28f20a9d3d8d51cffffbee22f8b9b2a75c3e6acdc7508224a03c286ef79d9c5ba6b08e1db4d65a79bc947c6a06141d6a7faca5d4fcb1421274f7ef97f1eeb35f04001e9209df2a18c1c41084d40e614c554853ed7f85dbca08df1727c367606a12a08ef781442ab4d951a7943a8db7397d6d979cc0572a10cba0fc5c1d35c4bb5a79657d25f3d15fd863f8b15e1cd58ee41ac5788628487efeada070f8e2d3cbfc96c16a3d53ec257f70586b0bd43f89bc0db9e685dab211af9e1df858bac91987b8dcd7d9b2c8afe5050cd9f0f77c7e60f327d347dd1589ba6e39a7666e995d80bc9cdef151f228c375d483fc1f9307c857ca5ca12ae7a9863773251286bb7e8a987579546cef833833fe15e43ca671c8e499c071c24c9b5c8b690f45dfa27631d3e47561227e1738c92f6b4785417a6c61057e1c321b8a51d15a9f585f8d348d5ea661df3e79df347874b3d989e86c5407e73457b130f9a6ee2518e78e86e8007c0e6e4d6c6
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73342);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-2112");
  script_bugtraq_id(66462);
  script_osvdb_id(104970);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuf51357");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140326-ios-sslvpn");

  script_name(english:"Cisco IOS Software SSL VPN Denial of Service (cisco-sa-20140326-ios-sslvpn)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS
running on the remote host is affected by a denial of service
vulnerability due to improper handling of certain, unspecified types
of HTTP requests in the SSL VPN subsystem. An unauthenticated, remote
attacker could potentially exploit this issue by sending specially
crafted HTTP requests resulting in a denial of service.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140326-ios-sslvpn
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d99d5315");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=33350");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20140326-ios-sslvpn.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/04");

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

flag = 0;
override = 0;
report = "";
fixed_ver = "";
cbi = "CSCuf51357";

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

#15.1GC
if (ver == "15.1(2)GC" ||  ver == "15.1(2)GC1" ||  ver == "15.1(2)GC2" ||  ver == "15.1(4)GC" ||  ver == "15.1(4)GC1" ||  ver == "15.1(4)GC2")
  fixed_ver = "15.1(4)M7";
#15.1M
else if (ver == "15.1(4)M" ||  ver == "15.1(4)M0a" ||  ver == "15.1(4)M0b" ||  ver == "15.1(4)M1" ||  ver == "15.1(4)M2" ||  ver == "15.1(4)M3" ||  ver == "15.1(4)M3a" ||  ver == "15.1(4)M4" ||  ver == "15.1(4)M5" ||  ver == "15.1(4)M6")
  fixed_ver = "15.1(4)M7";
#15.1T
else if (ver == "15.1(2)T" ||  ver == "15.1(2)T0a" ||  ver == "15.1(2)T1" ||  ver == "15.1(2)T2" ||  ver == "15.1(2)T2a" ||  ver == "15.1(2)T3" ||  ver == "15.1(2)T4" ||  ver == "15.1(2)T5" ||  ver == "15.1(3)T" ||  ver == "15.1(3)T1" ||  ver == "15.1(3)T2" ||  ver == "15.1(3)T3" ||  ver == "15.1(3)T4")
  fixed_ver = "15.1(4)M7";
#15.1XB
else if (ver == "15.1(4)XB4" ||  ver == "15.1(4)XB5" ||  ver == "15.1(4)XB5a" ||  ver == "15.1(4)XB6" ||  ver == "15.1(4)XB7" ||  ver == "15.1(4)XB8" ||  ver == "15.1(4)XB8a")
  fixed_ver = "Refer to the vendor for a fix.";
#15.2GC
else if (ver == "15.2(1)GC" ||  ver == "15.2(1)GC1" ||  ver == "15.2(1)GC2" ||  ver == "15.2(2)GC" ||  ver == "15.2(3)GC" ||  ver == "15.2(3)GC1" ||  ver == "15.2(4)GC")
  fixed_ver = "15.2(4)GC1";
#15.2GCA
else if (ver == "15.2(3)GCA" ||  ver == "15.2(3)GCA1")
  fixed_ver = "Refer to the vendor for a fix.";
#15.2M
else if (ver == "15.2(4)M" ||  ver == "15.2(4)M1" ||  ver == "15.2(4)M2" ||  ver == "15.2(4)M3" ||  ver == "15.2(4)M4" ||  ver == "15.2(4)M5")
  fixed_ver = "15.2(4)M6";
#15.2T
else if (ver == "15.2(1)T" ||  ver == "15.2(1)T1" ||  ver == "15.2(1)T2" ||  ver == "15.2(1)T3" ||  ver == "15.2(1)T3a" ||  ver == "15.2(1)T4" ||  ver == "15.2(2)T" ||  ver == "15.2(2)T1" ||  ver == "15.2(2)T2" ||  ver == "15.2(2)T3" ||  ver == "15.2(2)T4" ||  ver == "15.2(3)T" ||  ver == "15.2(3)T1" ||  ver == "15.2(3)T2" ||  ver == "15.2(3)T3" ||  ver == "15.2(3)T4")
  fixed_ver = "15.2(4)M6";
#15.2XA
else if (ver == "15.2(3)XA")
  fixed_ver = "Refer to the vendor for a fix.";
#15.2XB
else if (ver == "15.2(4)XB10")
  fixed_ver = "Refer to the vendor for a fix.";
#15.3M
else if (ver == "15.3(3)M" ||  ver == "15.3(3)M1")
  fixed_ver = "15.3(3)M2";
#15.3T
else if (ver == "15.3(1)T" ||  ver == "15.3(1)T1" ||  ver == "15.3(1)T2" ||  ver == "15.3(1)T3" ||  ver == "15.3(2)T" ||  ver == "15.3(2)T1" ||  ver == "15.3(2)T2")
  fixed_ver = "15.3(1)T4 / 15.3(2)T3";
#15.4CG
else if (ver == "15.4(1)CG")
  fixed_ver = "Refer to the vendor for a fix.";
#15.4S
else if (ver == "15.4(1)S")
  fixed_ver = "15.4(1)S1";
#15.4T
else if (ver == "15.4(1)T")
  fixed_ver = "15.4(1)T1";

if (fixed_ver) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      m = eregmatch(pattern:"webvpn gateway([^!]+)!", string:buf);
      if ( (!isnull(m)) && ("inservice" >< m[1]) ) { flag = 1; }
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
