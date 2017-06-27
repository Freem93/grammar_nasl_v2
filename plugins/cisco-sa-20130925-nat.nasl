#TRUSTED 3b2264f341d7af398676aba79c83e4a2124b6c88a40c877ed0d770a7a35b7c5a40043aab678fb078049b6355a7656c4b071bb6ac075c7598f50fc0bd3cb20ec94c1d44d0d4edcec5a8e80d698a0e3559526e203e8f8e161230f529d0bcaf883ea10f2156da5b16246e47157052aaeb1b2e333f6dd29608c725744fc23a3fc8d1ca33b29a658693cc56fedee023fa19f6268eac8689de94fd6e6ba3bbaa68bcb7d3171cd10b71234edd466da1466527e253163d4a37357898301ca98094b084913d304fa69feb8da5d33299f1fb28dc5a6c246bd51139c72c2e8e6a416eb83eb9dd0fa074951667f22c2ba64a49b1cb70291cb9026a9b37f2856fe443312b6acd8392771e6e843f8d2fbe8a2ebc7f841a98a7325ff58ab444b37c628ad2ec7add38c665a0ceb9e7e02cdd946979df73a3d7dfd7cde2690a9ba19480c4bc1636ede015601e4c712e78fac9534da308a0c2348f07484b1e36e3ec702c5a2d692298663a5ac681016ba040c0ea6560141abed2f16a1d7a8538f9c06a268ab38894c0052392c6c805c7aa0f003ad3a6717dc8f69f7282cf7673a80fcf382699093dc8401576450371f1346fb5614e6e2adde3fa5e3aa2dc3d833e2f21158c0e6bf8cdbce7a96831eb3f055b087b2c7760eb603b109bac9784f6398a249e2884769b732c99619bfbe3aa0c668b2e8aff6fe317305a6f7e51ad4bdfec3be2ca6588a48d
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20130925-nat.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(70320);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/07/03");

  script_cve_id("CVE-2013-5479", "CVE-2013-5480", "CVE-2013-5481");
  script_bugtraq_id(62637, 62639, 62641);
  script_osvdb_id(97738, 97739, 97740);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtn53730");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtq14817");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuf28733");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130925-nat");

  script_name(english:"Cisco IOS Software Network Address Translation Vulnerabilities (cisco-sa-20130925-nat)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Cisco IOS Software implementation of the network address
translation (NAT) feature contains three vulnerabilities when
translating IP packets that could allow an unauthenticated, remote
attacker to cause a denial of service (DoS) condition. Cisco has
released free software updates that address these vulnerabilities.
Workarounds that mitigate these vulnerabilities are not available."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130925-nat
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b7525ca9"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20130925-nat."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/07");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
if ( version == '12.2(33)SXI7' ) flag++;
if ( version == '12.2(33)SXJ1' ) flag++;
if ( version == '12.2(50)SY3' ) flag++;
if ( version == '12.2(50)SY4' ) flag++;
if ( version == '15.0(1)M6' ) flag++;
if ( version == '15.0(1)M6a' ) flag++;
if ( version == '15.0(1)M7' ) flag++;
if ( version == '15.0(1)SY' ) flag++;
if ( version == '15.1(2)T4' ) flag++;
if ( version == '15.1(3)T' ) flag++;
if ( version == '15.1(3)T1' ) flag++;
if ( version == '15.1(3)T2' ) flag++;
if ( version == '15.1(3)T3' ) flag++;
if ( version == '15.1(3)T4' ) flag++;
if ( version == '15.1(4)GC' ) flag++;
if ( version == '15.1(4)GC1' ) flag++;
if ( version == '15.1(4)M' ) flag++;
if ( version == '15.1(4)M0a' ) flag++;
if ( version == '15.1(4)M0b' ) flag++;
if ( version == '15.1(4)M1' ) flag++;
if ( version == '15.1(4)M2' ) flag++;
if ( version == '15.1(4)M3' ) flag++;
if ( version == '15.1(4)M3a' ) flag++;
if ( version == '15.1(4)M4' ) flag++;
if ( version == '15.1(4)M5' ) flag++;
if ( version == '15.1(4)M6' ) flag++;
if ( version == '15.1(4)XB4' ) flag++;
if ( version == '15.1(4)XB5' ) flag++;
if ( version == '15.1(4)XB5a' ) flag++;
if ( version == '15.1(4)XB6' ) flag++;
if ( version == '15.1(4)XB7' ) flag++;
if ( version == '15.1(4)XB8a' ) flag++;
if ( version == '15.2(1)GC' ) flag++;
if ( version == '15.2(1)GC1' ) flag++;
if ( version == '15.2(1)GC2' ) flag++;
if ( version == '15.2(1)T' ) flag++;
if ( version == '15.2(1)T1' ) flag++;
if ( version == '15.2(1)T2' ) flag++;
if ( version == '15.2(1)T3' ) flag++;
if ( version == '15.2(1)T3a' ) flag++;
if ( version == '15.2(1)T4' ) flag++;
if ( version == '15.2(2)GC' ) flag++;
if ( version == '15.2(2)JA' ) flag++;
if ( version == '15.2(2)JA1' ) flag++;
if ( version == '15.2(2)JAX' ) flag++;
if ( version == '15.2(2)JB' ) flag++;
if ( version == '15.2(2)JB1' ) flag++;
if ( version == '15.2(2)T' ) flag++;
if ( version == '15.2(2)T1' ) flag++;
if ( version == '15.2(2)T2' ) flag++;
if ( version == '15.2(2)T3' ) flag++;
if ( version == '15.2(3)GC' ) flag++;
if ( version == '15.2(3)GC1' ) flag++;
if ( version == '15.2(3)GCA' ) flag++;
if ( version == '15.2(3)T' ) flag++;
if ( version == '15.2(3)T1' ) flag++;
if ( version == '15.2(3)T2' ) flag++;
if ( version == '15.2(3)T3' ) flag++;
if ( version == '15.2(3)XA' ) flag++;
if ( version == '15.2(4)JA' ) flag++;
if ( version == '15.2(4)M' ) flag++;
if ( version == '15.2(4)M1' ) flag++;
if ( version == '15.2(4)M2' ) flag++;
if ( version == '15.2(4)M3' ) flag++;
if ( version == '15.2(4)XB10' ) flag++;
if ( version == '15.3(1)T' ) flag++;
if ( version == '15.3(1)T1' ) flag++;
if ( version == '15.3(2)T' ) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"\s+ip\s+nat\s+[eio]", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
