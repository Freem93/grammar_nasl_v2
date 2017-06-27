#TRUSTED 18061655b6fdf09f9b6f81cbced4f10d0e7fa01a2886f4cf6aa4eb711d4d2e7adefd33bbc6c558b2fe5415ffd10aa332d044677e591547d75e59e7e9ea717d095be7740a5a148f7e77714fbe9c01d2ad7936b58c648ea6a4da764dde7b825c2d76339c33348105f5539956964f0638eb3e6a48767ace70c14657a559f8413e7b3e810475bdeddfae340ceb9dc3a6505cf594a1a73b0cfceac7e912b81124ce973c2053d32359666cf178fc1b4421fb88a082c721c1e2d5c0667683a46518187a89d477a02997054915f94eba170d0a1daccc2bdea2f7171d931232b201eec8f89e5c72ca141d2566e6e33c73f9221a1deea46bb6d56f840d7c0334b5e92441f539dd0b4827617c468c238647eee6ca73b7b7046ba4c1b0c5086e63bbb8aaea46279e593820058ec7204884b153e6117b3bc1b15ec9397acde1d1f5c2cc51ec19d7c4315b16d09543445e95e913d3d0f9386d192fb35433f0194556b11731fb911ce9f256bc38efecdbec39e4b78f0061b4682dd590b067aec8b6644e5584175a16cd82f3075712cd7c98c604e31b18968aff07f22bce3323abae2f44d11a0f571f0ac95a95a9d1a186b5e55bf22d6122092b5f8641fbcd8842241aa430a5751e270aabe087c31f83a29d911543efb897fea88890733c1ce3cf34a2e8f9e0101f72ec5d9d11fadc01112dea5d921c597df2d7d80228dc17e194239a089b219a87
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a0080af8119.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(49039);
 script_version("1.16");
 script_set_attribute(attribute:"plugin_modification_date", value:"2014/08/11");
 script_cve_id("CVE-2009-2862");
 script_bugtraq_id(36495);
 script_osvdb_id(58338);
 script_xref(name:"CISCO-BUG-ID", value:"CSCsu50252");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsu70214");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsv48603");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsw47076");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsx07114");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsy54122");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20090923-acl");
 script_name(english:"Cisco IOS Software Object-group Access Control List Bypass Vulnerability - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
'A vulnerability exists in Cisco IOS software where an unauthenticated
attacker could bypass access control policies when the Object Groups
for Access Control Lists (ACLs) feature is used. Cisco has released
free software updates that address this vulnerability. There are no
workarounds for this vulnerability other than disabling the Object
Groups for ACLs feature.
');
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3cb1587e");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a0080af8119.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?1868db4d");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20090923-acl.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(264);
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/23");
 script_set_attribute(attribute:"patch_publication_date", value:"2009/09/23");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_end_attributes();
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2010-2014 Tenable Network Security, Inc.");
 script_family(english:"CISCO");
 script_dependencie("cisco_ios_version.nasl");
 script_require_keys("Host/Cisco/IOS/Version");
 exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

if (version == '12.4(22)YE') flag++;
else if (version == '12.4(22)YD') flag++;
else if (version == '12.4(22)YB1') flag++;
else if (version == '12.4(22)YB') flag++;
else if (version == '12.4(20)YA3') flag++;
else if (version == '12.4(20)YA2') flag++;
else if (version == '12.4(20)YA1') flag++;
else if (version == '12.4(20)YA') flag++;
else if (version == '12.4(15)XZ2') flag++;
else if (version == '12.4(15)XZ1') flag++;
else if (version == '12.4(15)XZ') flag++;
else if (version == '12.4(24)T') flag++;
else if (version == '12.4(22)T1') flag++;
else if (version == '12.4(22)T') flag++;
else if (version == '12.4(20)T3') flag++;
else if (version == '12.4(20)T2') flag++;
else if (version == '12.4(20)T1') flag++;
else if (version == '12.4(20)T') flag++;
else if (version == '12.4(22)MF') flag++;
else if (version == '12.4(22)MDA') flag++;
else if (version == '12.4(22)MD') flag++;
else if (version == '12.4(22)GC1') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show object-group", "show object-group");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"Network object group ", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}



if (flag)
{
  security_warning(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
