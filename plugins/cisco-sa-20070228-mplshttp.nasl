#TRUSTED 21f064f50402a965c64e1100399abc4fa0537b3e78e8c08f6bd324bae574b39cf2ba091087f4159de89b3bff50b76cb38a7c08e920ec5191a4649027c2a594b13bb709b3aab1ff42515dc1a8ef0199fe27d1a737ab2899ead1842a892bdc9f488c2be10edbfa86a69b299caa24b1b90a811df7616b590637e6a3df9ea927ddf320ff6c9305f97cdcf4c4cf2f29b6b01d81952dc0eed10aec355c79d2c818fdde6178c5b991fde6f575b1b89fa643887784a122bcf4f515eb595b569a6e4f15694105f054b14bb0d979750618d1fa7335041e0e6fbe7507ad128d854510e581c50a3d1543cdb4200ac8981e7c3da4a6896f9afcb88a52177536bd99cb6ec801d29c03e556350ae2e495e583edd9c22734d9d287813de74ef357e5ca09845538552f7eb6d6bdb3505d0cf97f9de4221e11fdab0830cffe1e2567a73dc71430404e4a40a4b6cca4866d727f6c4b6c8351a6a0ffa01bc4a619135218062336a4e05b83616abca785e7fda90b087473a5bf04d41fb6fe327a8aa790b5aeb4f9186d48085ac703b1f0e50a17e70d5a7c4d3007805881710b5a3ea0d91b8b06251bb769f86824e25ed5596b73eb20c9e8263c6aa8515d2e783bc169bf3dcd8d456a928bd8de07906b19dc2e6619686468f041b869ae2cb58cd6b30eb41aa589bb146c728ebcf84a51d3883d868b746a5511d84b965367cd2de579cf67e5c6388b4604d1
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a00807f413e.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(49001);
 script_version("1.12");
 script_set_attribute(attribute:"plugin_modification_date", value:"2014/08/11");
 script_cve_id("CVE-2007-1258");
 script_osvdb_id(33067);
 script_name(english:"Cisco Catalyst 6000, 6500 and Cisco 7600 Series MPLS Packet Vulnerability");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
'Cisco Catalyst 6500 series systems that are running certain versions of
Cisco Internetwork Operating System (IOS) are vulnerable to an attack
from a Multi Protocol Label Switching (MPLS) packet. Only the systems
that are running in Hybrid Mode (Catalyst OS (CatOS) software on the
Supervisor Engine and IOS Software on the Multilayer Switch Feature
Card (MSFC)) or running with Cisco IOS Software Modularity are
affected.
MPLS packets can only be sent from the local network segment.
');
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0e6ad627");
 # http://www.cisco.com/en/US/products/products_security_advisory09186a00807f413e.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?9b184f9d");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20070228-mpls.");
 script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/28");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/02/28");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCef90002");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsd37415");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20070228-mpls");
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
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
override = 0;

if (version == '12.2(18)SXD1') flag++;
else if (version == '12.2(17d)SXB4') flag++;
else if (version == '12.2(17d)SXB3') flag++;
else if (version == '12.2(17d)SXB2') flag++;
else if (version == '12.2(17d)SXB1') flag++;
else if (version == '12.2(17b)SXA2') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"s72033-adventerprisek9_wan-vz.122-18.SXF4.bin", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"s72033-advipservicesk9_wan-vz.122-18.SXF4.bin", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"s72033-entservicesk9_wan-vz.122-18.SXF4.bin", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"s72033-ipservices_wan-vz.122-18.SXF4.bin", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"s72033-ipservicesk9_wan-vz.122-18.SXF4.bin", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"s72033-ipservicesk9-vz.122-18.SXF4.bin", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_warning(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
