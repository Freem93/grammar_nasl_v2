#TRUSTED 22aed648ab95112a651b7ff0706f23fc2ee3be14fe508d7d1e894861f769bf7f1ecfb5b59b962f4d8c543587b92f4a9ae8cd99136f21224fa4e4e6fb88fdf687652946f0aeeda8c5d51ca46eeddcf9f8a2b3433b2b754d8388658e49b48d077c961bf149fac42c77bd324382db5bdff04da9fef972a6bfe7a8bd7df637a9e2af247f0cd8b29204d155da23b87497525cd9e225fc26c91026c33d93797c52a27512e0343e95b8beb8a3f4ec9fb32a43b9d2742cb51f13f8d68c4542d0798cc853fd8135ea6ec9ad57a67e96d9f52a3923076fdf74445f25bb9eae115ebc6af086644b28a99284d873582389ae2ecef5e18f59cd07f75d52ee4f6263848d0128eedf726dc0ff580ec87b37baec3acd5bc7757824dd776cb1308b8f6cb2dc54e99685598713192b98f0b12df77b0c8c1d0988b757897e5296992ff3e3b88c05cef57c1ca5d27f272d517d24dcc3aaaf62a0bd6d1d8c7fa7829ef6100548e82a751afa22f38284901eefa3cd146d7ef266c4619fb9e6cb108b35a56a5fa61e98c35654eca7cf775c0d6da8f976dcbf156d368fde916f02f3156a8d62cec27be8dce9b3b88069241af3a6e6e7b4297c17a8f5faaa41dc9c33215956a94facbdc551ae38cbcd54558f9748941463019cc59f243413c89f13778e0ecc1c22e6f7e390898be8e25c2cb6170a590272168c0f6b1adec157338a3678ce75aec63203d94fda
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a008011c3b4.shtml

include("compat.inc");

if (description)
{
  script_id(48968);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/08/11");

  script_cve_id("CVE-2002-1357", "CVE-2002-1358", "CVE-2002-1359", "CVE-2002-1360");
  script_bugtraq_id(6405, 6407, 6408, 6410);
  script_osvdb_id(8042, 8043, 8044, 8045);
  script_xref(name:"CERT-CC", value:"389665");
  script_xref(name:"CERT-CC", value:"CA-2002-36");
  script_xref(name:"CISCO-BUG-ID", value:"CSCdu75477");
  script_xref(name:"CISCO-BUG-ID", value:"CSCdy87221");
  script_xref(name:"CISCO-BUG-ID", value:"CSCdz07673");
  script_xref(name:"CISCO-BUG-ID", value:"CSCdz60229");
  script_xref(name:"CISCO-BUG-ID", value:"CSCdz62330");
  script_xref(name:"CISCO-BUG-ID", value:"CSCdz66748");
  script_xref(name:"CISCO-BUG-ID", value:"CSCeb16775");
  script_xref(name:"CISCO-BUG-ID", value:"CSCed38362");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20021219-ssh-packet");

  script_name(english:"SSH Malformed Packet Vulnerabilities - Cisco Systems");
  script_summary(english:"Checks IOS version");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"Certain Cisco products containing support for the Secure Shell (SSH)
server are vulnerable to a Denial of Service (DoS) if the SSH server is
enabled on the device. A malformed SSH packet directed at the affected
device can cause a reload of the device. No authentication is necessary
for the packet to be received by the affected device. The SSH server in
Cisco IOS is disabled by default.

Cisco will be making free software available to correct the problem as
soon as possible.

The malformed packets can be generated using the SSHredder test suite
from Rapid7, Inc. Workarounds are available. The Cisco PSIRT is not
aware of any malicious exploitation of this vulnerability.");
  script_set_attribute(attribute:"see_also", value:"http://www.rapid7.com/security-center/advisories/R7-0009.jsp");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20021219-ssh-packet
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aed52b80");
  # http://www.cisco.com/en/US/products/products_security_advisory09186a008011c3b4.shtml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?212f29f0");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20021219-ssh-packet");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PuTTY Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/12/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2002/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
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
report_extra = "";
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
override = 0;

# Affected: 12.0S
if (check_release(version: version,
                  patched: make_list("12.0(21)S6", "12.0(22)S4", "12.0(23)S2"),
                  oldest: "12.0(5)S")) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0ST
if (check_release(version: version,
                  patched: make_list("12.0(20)ST7", "12.0(21)ST6"),
                  oldest: "12.0(16)ST")) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1E
if (check_release(version: version,
                  patched: make_list("12.1(13)E3", "12.1(14)E1"),
                  oldest: "12.1(5a)E")) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1EA
if (check_release(version: version,
                  patched: make_list("12.1(13)EA1") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.1T
if (deprecated_version(version, "12.1T")) {
 report_extra = '\nNo fix is available for 12.1T releases. Upgrade to a supported version\n'; flag++;
}
# Affected: 12.2
if (check_release(version: version,
                  patched: make_list("12.2(12b)", "12.2(13a)"),
                  oldest: "12.2(1)")) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2S
if (check_release(version: version,
                  patched: make_list("12.2(14)S"),
                  oldest: "12.2(1)S")) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2T
if (check_release(version: version,
                  patched: make_list("12.2(11)T3", "12.2(13)T1") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}

if (get_kb_item("Host/local_checks_enabled"))
{

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_ssh", "show ip ssh");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"SSH\s+Enabled", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}



if (flag)
{
  security_hole(port:0, extra:report_extra + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

